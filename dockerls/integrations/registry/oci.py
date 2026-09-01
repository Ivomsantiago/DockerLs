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
    from collections.abc import Callable, Sequence

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

#: Safety cap on `Link: rel="next"` pagination of a tag listing. A registry
#: that always advertises another page -- by bug or by design -- must not
#: be followed forever; real catalogues, even large ones, finish in a
#: handful of pages long before this.
MAX_TAG_PAGES = 50

#: Requested page size for the *first* tag listing request. The Distribution
#: v2 spec's `?n=<count>` is the registry's own paging control, and without
#: it a repository falls back to whatever the registry's default page is --
#: as few as a few dozen tags per page for some hosts. `cgr.dev` in
#: particular publishes hundreds of tags per repository, which turned a
#: single-page request into a dozen-plus sequential round trips once
#: pagination started being followed. Asking for a large page up front
#: collapses that back to one request for the overwhelming majority of
#: repositories; `MAX_TAG_PAGES` still guards the rest.
INITIAL_PAGE_SIZE = 1000


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
        # Repositories whose cached listing is known-complete (fetched
        # without a `stop_when`, or one whose last page had no `next`
        # link). A repository *absent* from this set but present in
        # `_listings` was cached from a `stop_when`-bounded fetch that
        # stopped before the end -- reusable for a later call whose own
        # `stop_when` is already satisfied by it, but not authoritative for
        # a call that wants the full listing.
        self._complete: set[str] = set()
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

    async def list_tags(
        self,
        repository: str,
        *,
        stop_when: Callable[[Sequence[str]], bool] | None = None,
    ) -> dict[str, Any] | None:
        """Return the raw `/v2/<repository>/tags/list` payload, or None when
        the repository does not exist or cannot be reached.

        Memoised per repository for the lifetime of this client, including
        the `None` outcome: a repository that does not exist should be asked
        about once, not once per candidate.

        `stop_when(tags)` is checked after every page and, when it returns
        True, pagination stops there instead of continuing to
        `MAX_TAG_PAGES`. Some catalogues (Chainguard's in particular) list
        cosign signature/attestation tags alongside real ones, so a
        repository with a handful of runnable images can still take dozens
        of pages to list in full -- and a caller that only needs a handful
        of tags has no reason to pay for the rest.

        A `stop_when`-bounded fetch is cached too -- so `tag_exists` on a
        tag `search_tags` just returned still costs nothing extra -- but
        only as *sufficient for a predicate already satisfied by it*: it is
        not a complete listing, and a later caller that wants the full one
        (`stop_when=None`, or a predicate this cache does not already
        satisfy) triggers a fresh fetch rather than silently answering from
        a truncated cache.
        """
        cached, has_cached = self._cached_if_usable(repository, stop_when)
        if has_cached:
            return cached

        lock = self._listing_locks.setdefault(repository, asyncio.Lock())
        async with lock:
            # A concurrent caller may have filled it while we waited.
            cached, has_cached = self._cached_if_usable(repository, stop_when)
            if has_cached:
                return cached
            payload, complete = await self._fetch_tags(repository, stop_when=stop_when)
            self._listings[repository] = payload
            if complete:
                self._complete.add(repository)
            else:
                self._complete.discard(repository)
            return payload

    def _cached_if_usable(
        self, repository: str, stop_when: Callable[[Sequence[str]], bool] | None
    ) -> tuple[dict[str, Any] | None, bool]:
        """The cached listing for `repository` if it answers this call, and
        whether one was found at all (`None` is itself a valid cached
        answer -- "confirmed missing" -- so it cannot double as "no
        entry")."""
        if repository not in self._listings:
            return None, False
        cached = self._listings[repository]
        if repository in self._complete or cached is None:
            return cached, True
        if stop_when is not None and stop_when(cached.get("tags") or []):
            return cached, True
        return None, False

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

    @staticmethod
    def _next_page_url(resp: httpx.Response, base_url: str) -> str | None:
        """The absolute URL of the next page, from a `Link: <...>; rel="next"`
        response header (GHCR, Harbor, Artifactory), or None on the last page.

        `httpx.Response.links` parses the header but leaves a relative
        target exactly as advertised; it is resolved against the URL that
        was actually requested, not `self._host` directly, so a registry
        that names an absolute URL on a different path or port is followed
        as it asked.
        """
        next_link = resp.links.get("next")
        target = next_link.get("url") if next_link else None
        if not target:
            return None
        return str(httpx.URL(base_url).join(target))

    async def _fetch_tags(
        self,
        repository: str,
        *,
        stop_when: Callable[[Sequence[str]], bool] | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Fetch every page of `/v2/<repository>/tags/list`, merging `tags`.

        GHCR, Harbor and Artifactory paginate a large tag listing via the
        `Link` response header rather than returning it all in one body.
        Followed here, page by page, up to `MAX_TAG_PAGES` -- a registry
        that always advertises another `next` link (deliberately or by a
        pagination bug) must not hang this process forever; whatever was
        gathered up to the cap is returned rather than discarded, with a
        warning that the listing may be incomplete.

        `stop_when`, when given, is also checked after every page and ends
        the fetch early -- see `list_tags` for why a caller would want that.

        Returns `(payload, complete)`. `complete` is True when `stop_when`
        was never given (the caller wanted everything, so whatever came
        back is treated as authoritative, same as before `stop_when`
        existed) or when the last page's `Link` header had no `next` --
        i.e. this genuinely was the end of the listing, regardless of why
        the loop stopped checking for more.
        """
        url = f"https://{self._host}/v2/{repository}/tags/list?n={INITIAL_PAGE_SIZE}"
        headers: dict[str, str] = {}
        try:
            client = await self._get_client()
            resp = await self._request(client, "GET", url, headers)
            if resp.status_code == 401:
                token = await self._token(client, resp.headers.get("WWW-Authenticate", ""))
                if not token:
                    logger.warning(f"No anonymous token available for {self._host}")
                    return None, True
                headers = {"Authorization": f"Bearer {token}"}
                resp = await self._request(client, "GET", url, headers)

            if resp.status_code == 404:
                logger.info(f"Repository not found: {self._host}/{repository}")
                return None, True
            resp.raise_for_status()
            payload: dict[str, Any] = resp.json()
            all_tags = list(payload.get("tags") or [])

            pages = 1
            page_url = url
            next_url = self._next_page_url(resp, page_url)
            while next_url is not None and not (stop_when is not None and stop_when(all_tags)):
                if pages >= MAX_TAG_PAGES:
                    logger.warning(
                        f"Tag listing for {self._host}/{repository} exceeded "
                        f"{MAX_TAG_PAGES} pages; returning the {len(all_tags)} tags "
                        "gathered so far instead of following it further"
                    )
                    break
                page_resp = await self._request(client, "GET", next_url, headers)
                if not page_resp.is_success:
                    logger.warning(
                        f"Tag listing page for {self._host}/{repository} answered "
                        f"{page_resp.status_code}; returning the {len(all_tags)} tags "
                        "gathered so far"
                    )
                    break
                page_payload = page_resp.json()
                if not isinstance(page_payload, dict):
                    break
                all_tags.extend(page_payload.get("tags") or [])
                pages += 1
                page_url = next_url
                next_url = self._next_page_url(page_resp, page_url)

            payload["tags"] = all_tags
            complete = stop_when is None or next_url is None
            return payload, complete
        except (httpx.HTTPError, ValueError, CircuitOpenError) as e:
            logger.warning(f"Tag listing failed for {self._host}/{repository}: {e}")
            return None, True
