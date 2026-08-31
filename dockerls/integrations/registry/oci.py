from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any

import httpx
from loguru import logger

from dockerls.infrastructure.network.guarded_client import guarded_async_client
from dockerls.utils.rate_limit import CircuitBreaker, CircuitOpenError, RateLimiter
from dockerls.utils.retry import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_MAX_ATTEMPTS,
    retry_policy,
)

if TYPE_CHECKING:
    from dockerls.infrastructure.network.host_guard import HostGuard

#: Requests per second this client paces itself to, per registry host. A
#: generic OCI registry publishes no documented budget the way Docker Hub
#: or GitHub do, so this is a conservative default that protects against a
#: self-inflicted burst (many concurrent tag/candidate lookups against the
#: same host) rather than a number tuned to any one registry's real limit.
_REGISTRY_RATE = 10
_REGISTRY_PERIOD = 1.0

# Cosign and friends publish their signatures, attestations and SBOMs as
# ordinary tags in the same repository. They are not runnable images, so
# they must never reach the scan pipeline.
_ARTIFACT_TAG = re.compile(
    r"""
    ^sha256[-:]            # cosign artifacts: sha256-<digest>.sig/.att/.sbom
  | \.(sig|att|sbom)$
  | ^deprecated-public-image-
    """,
    re.VERBOSE,
)

# Single-architecture aliases of a multi-arch tag ("16-amd64"). Scanning them
# adds duplicates of a tag we already have.
_ARCH_SUFFIX = re.compile(r"-(amd64|arm64|arm|armv[567]|386|ppc64le|s390x|riscv64|mips64le|wasm)$")

# Provenance-pinned variants -- either suffixed ("debug-nonroot-165b5d63...")
# or a bare commit hash -- point at the same image as their base tag.
# Distroless publishes dozens per release; unfiltered they crowd out every
# distinct image in the listing.
_COMMIT_TAG = re.compile(r"(-[0-9a-f]{32,}$|^[0-9a-f]{32,}$)")


#: Manifests and config blobs are kilobytes. A registry (or something
#: pretending to be one) answering with more than this is not serving
#: metadata, and the body is discarded rather than parsed.
MAX_BLOB_BYTES = 8 * 1024 * 1024


def is_runnable_tag(tag: str) -> bool:
    """True for tags that name a distinct image a user would actually pull."""
    if not tag or _ARTIFACT_TAG.search(tag):
        return False
    if _COMMIT_TAG.search(tag):
        return False
    return not _ARCH_SUFFIX.search(tag)


def parse_www_authenticate(header: str) -> tuple[str, dict[str, str]]:
    """Split a `Bearer realm="...",service="...",scope="..."` challenge into
    (realm, params)."""
    if not header.lower().startswith("bearer"):
        return "", {}
    params = dict(re.findall(r'(\w+)="([^"]*)"', header))
    return params.pop("realm", ""), params


def is_fetchable_realm(realm: str) -> bool:
    """Whether a `WWW-Authenticate` realm is a URL we will actually fetch.

    Requires an absolute http/https URL with a host. That rules out
    `file://`, `gopher://` and the schemeless forms; *where* the host may be
    is the network policy's business, enforced per hop by the guarded
    client, and is deliberately not re-decided here.
    """
    try:
        url = httpx.URL(realm)
    except (httpx.InvalidURL, ValueError, TypeError, UnicodeError):
        return False
    return url.scheme in ("http", "https") and bool(url.host)


class OCIRegistryClient:
    """Minimal OCI Distribution v2 client for listing tags.

    Implements only the anonymous pull-scope token dance that public
    registries use: request the endpoint, and if it answers 401 with a
    Bearer challenge, fetch a token from the advertised realm and retry.

    A listing is fetched **once per repository per run**. `recommend` asks
    for the same listing many times over -- once during discovery, then once
    more for every candidate whose tag `_verify_tags` confirms -- and each
    call previously opened a fresh connection, ate a 401, fetched a token,
    and re-downloaded a payload identical to the one it already had. For a
    single repository with ten candidates that is 33 requests where 3 do the
    job.

    Three things close that gap, and they compose:

    * One `httpx.AsyncClient` for the client's lifetime, so connections and
      the TLS handshake are reused (HTTP keep-alive) instead of rebuilt.
    * A per-repository result cache.
    * A per-repository lock, so ten *concurrent* first calls collapse into
      one request rather than ten -- a cache with no single-flight guard
      would still stampede, because verification runs them in parallel.

    The cache lives on the instance, so it lasts exactly one run and cannot
    serve a listing from a previous invocation.
    """

    def __init__(
        self,
        host: str,
        timeout: int = 30,
        guard: HostGuard | None = None,
        *,
        username: str = "",
        password: str = "",
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        self._host = host
        self._timeout = timeout
        # Redirects are followed, and the token realm is a URL this registry
        # chooses. Both are hops the caller's up-front check on `host` says
        # nothing about, so the guard travels with the client.
        self._guard = guard
        # Basic credentials for the token endpoint -- the standard Docker
        # Registry HTTP API V2 flow every private registry this client
        # targets (ECR, Harbor, GHCR, a generic OCI registry) implements the
        # same way: the 401 challenge names a realm, and that realm accepts
        # HTTP Basic auth in exchange for a scoped bearer token. Empty
        # strings mean anonymous, unchanged from before this parameter
        # existed.
        self._username = username
        self._password = password
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()
        self._listings: dict[str, dict[str, Any] | None] = {}
        self._listing_locks: dict[str, asyncio.Lock] = {}
        # One limiter/breaker per client, i.e. per registry host: a burst of
        # concurrent candidate lookups against the same registry is paced
        # rather than fired all at once, and a registry that is down stops
        # being retried request after request once it has failed enough in
        # a row.
        self._limiter = RateLimiter(rate=_REGISTRY_RATE, period=_REGISTRY_PERIOD)
        self._breaker = CircuitBreaker()

    @property
    def host(self) -> str:
        return self._host

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    self._client = guarded_async_client(
                        self._guard, timeout=self._timeout, follow_redirects=True
                    )
        return self._client

    async def close(self) -> None:
        """Release the shared connection pool."""
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    @staticmethod
    async def _request_once(
        client: httpx.AsyncClient, method: str, url: str, headers: dict[str, str]
    ) -> httpx.Response:
        """One HTTP request. A 5xx is turned into an exception so the retry
        policy above it can distinguish "the registry is having a bad
        moment" from a definitive answer (2xx/4xx), which is returned as-is
        for the caller to interpret."""
        resp = await client.request(method, url, headers=headers)
        if resp.status_code >= 500:
            resp.raise_for_status()
        return resp

    async def _request(
        self, client: httpx.AsyncClient, method: str, url: str, headers: dict[str, str]
    ) -> httpx.Response:
        """Retry policy + rate limit + circuit breaker around one request.

        Mirrors the pattern in `DockerHubClient._get_json` and
        `DHICatalogClient._get_text`: the policy is built fresh per call so
        `retry_max_attempts`/`retry_backoff_base` reach it, transient
        failures (network errors, 5xx) are retried, and a registry that
        keeps failing trips the breaker so further calls fail fast instead
        of repeating a doomed request.
        """
        self._breaker.check(self._host)
        await self._limiter.acquire()
        policy = retry_policy(self._max_attempts, self._backoff_base)
        try:
            resp: httpx.Response = await policy(self._request_once, client, method, url, headers)
        except httpx.HTTPError:
            self._breaker.record_failure()
            raise
        self._breaker.record_success()
        return resp

    async def _token(self, client: httpx.AsyncClient, challenge: str) -> str:
        realm, params = parse_www_authenticate(challenge)
        if not realm:
            return ""
        if not is_fetchable_realm(realm):
            # The realm is a URL chosen by the far end. Fetching whatever it
            # names turns any registry -- or anything on the path to one --
            # into a redirector pointing this process at the host's internal
            # network. An `https://` realm on a real registry is the norm;
            # anything else is refused before a socket is opened.
            logger.warning(f"Refusing token realm advertised by {self._host}: {realm!r}")
            return ""
        auth = (self._username, self._password) if self._username and self._password else None
        resp = await client.get(realm, params=params, auth=auth)
        resp.raise_for_status()
        data = resp.json()
        # Registries disagree on the field name; GCR/ECR use access_token.
        token: str = data.get("token") or data.get("access_token") or ""
        return token

    async def list_tags(self, repository: str) -> dict[str, Any] | None:
        """Return the raw `/v2/<repository>/tags/list` payload, or None when
        the repository does not exist or cannot be reached.

        Memoised per repository for the lifetime of this client, including
        the `None` outcome: a repository that does not exist should be asked
        about once, not once per candidate.
        """
        if repository in self._listings:
            return self._listings[repository]

        lock = self._listing_locks.setdefault(repository, asyncio.Lock())
        async with lock:
            # A concurrent caller may have filled it while we waited.
            if repository in self._listings:
                return self._listings[repository]
            payload = await self._fetch_tags(repository)
            self._listings[repository] = payload
            return payload

    async def get(
        self,
        path: str,
        *,
        accept: str = "",
        head: bool = False,
        max_bytes: int = MAX_BLOB_BYTES,
    ) -> httpx.Response | None:
        """One authenticated request against `/v2/<path>` on this registry.

        Performs the same anonymous token dance `_fetch_tags` uses, and
        bounds the response body: a manifest or config blob is a few
        kilobytes, and a registry answering with megabytes is either broken
        or hostile. Returns None on any failure, including an oversized
        body -- callers treat that as "could not determine", never as an
        empty result.
        """
        url = f"https://{self._host}/v2/{path}"
        headers = {"Accept": accept} if accept else {}
        method = "HEAD" if head else "GET"
        try:
            client = await self._get_client()
            resp = await self._request(client, method, url, headers)
            if resp.status_code == 401:
                token = await self._token(client, resp.headers.get("WWW-Authenticate", ""))
                if not token:
                    logger.info(f"No anonymous token available for {self._host}/{path}")
                    return None
                resp = await self._request(
                    client, method, url, {**headers, "Authorization": f"Bearer {token}"}
                )
        except (httpx.HTTPError, ValueError, CircuitOpenError) as e:
            logger.warning(f"Registry request failed for {self._host}/{path}: {e}")
            return None

        if not resp.is_success:
            logger.info(f"Registry answered {resp.status_code} for {self._host}/{path}")
            return None
        if not head and len(resp.content) > max_bytes:
            logger.warning(
                f"Registry response for {self._host}/{path} exceeded {max_bytes} bytes; discarded"
            )
            return None
        return resp

    async def _fetch_tags(self, repository: str) -> dict[str, Any] | None:
        url = f"https://{self._host}/v2/{repository}/tags/list"
        try:
            client = await self._get_client()
            resp = await self._request(client, "GET", url, {})
            if resp.status_code == 401:
                token = await self._token(client, resp.headers.get("WWW-Authenticate", ""))
                if not token:
                    logger.warning(f"No anonymous token available for {self._host}")
                    return None
                resp = await self._request(client, "GET", url, {"Authorization": f"Bearer {token}"})

            if resp.status_code == 404:
                logger.info(f"Repository not found: {self._host}/{repository}")
                return None
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
            return payload
        except (httpx.HTTPError, ValueError, CircuitOpenError) as e:
            logger.warning(f"Tag listing failed for {self._host}/{repository}: {e}")
            return None
