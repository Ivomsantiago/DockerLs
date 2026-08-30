from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any

import httpx
from loguru import logger

from dockerls.infrastructure.network.guarded_client import guarded_async_client

if TYPE_CHECKING:
    from dockerls.infrastructure.network.host_guard import HostGuard

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
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()
        self._listings: dict[str, dict[str, Any] | None] = {}
        self._listing_locks: dict[str, asyncio.Lock] = {}

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
        try:
            client = await self._get_client()
            resp = await client.request("HEAD" if head else "GET", url, headers=headers)
            if resp.status_code == 401:
                token = await self._token(client, resp.headers.get("WWW-Authenticate", ""))
                if not token:
                    logger.info(f"No anonymous token available for {self._host}/{path}")
                    return None
                resp = await client.request(
                    "HEAD" if head else "GET",
                    url,
                    headers={**headers, "Authorization": f"Bearer {token}"},
                )
        except (httpx.HTTPError, ValueError) as e:
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
            resp = await client.get(url)
            if resp.status_code == 401:
                token = await self._token(client, resp.headers.get("WWW-Authenticate", ""))
                if not token:
                    logger.warning(f"No anonymous token available for {self._host}")
                    return None
                resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})

            if resp.status_code == 404:
                logger.info(f"Repository not found: {self._host}/{repository}")
                return None
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
            return payload
        except (httpx.HTTPError, ValueError) as e:
            logger.warning(f"Tag listing failed for {self._host}/{repository}: {e}")
            return None
