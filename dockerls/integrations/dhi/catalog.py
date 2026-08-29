"""Read the Docker Hardened Images catalogue without downloading it.

The catalogue is a GitHub repository with roughly eleven thousand files. The
naive integration -- clone it, or walk `contents/` directory by directory --
is unusable twice over: an anonymous client gets 60 GitHub API requests per
hour, which a single `recommend node` would spend in one go, and a clone
costs tens of megabytes for the handful of definitions a query actually
needs.

So this client does two different things at two different rhythms:

* **once per TTL**, it fetches the repository's *tree* in a single API call
  and reduces it to a compact index (image -> variant -> definition files).
  The index is a few hundred kilobytes and answers "does DHI have node, and
  in which variants" with no network at all;
* **per query**, it fetches only the definition files the index names, from
  `raw.githubusercontent.com`, which is a CDN and does not consume the API
  budget.

Everything is cached through the same store the rest of the tool uses, with
the commit SHA carried alongside so a cached index can state which revision
of the catalogue it describes. Conditional requests (`If-None-Match`) let a
refresh cost nothing when the catalogue has not moved.

Trust boundary: every byte here arrives from the network. Paths that come
back from the tree API are validated against a strict pattern before being
turned into URLs, and definition bodies go through the bounded YAML loader.
A catalogue that answers with something unexpected yields *no candidates*,
never a candidate with invented properties.
"""

from __future__ import annotations

import asyncio
import json
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import httpx
from loguru import logger

from dockerls.integrations.dhi.definition import parse_definition
from dockerls.utils.rate_limit import CircuitBreaker, CircuitOpenError, RateLimiter
from dockerls.utils.safe_yaml import UnsafeYAMLError, safe_load_yaml

if TYPE_CHECKING:
    from dockerls.domain.entities.declared_metadata import DeclaredImageMetadata
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface

CATALOG_OWNER = "docker-hardened-images"
CATALOG_REPO = "catalog"
CATALOG_BRANCH = "main"

#: The two hosts this client is allowed to reach. Paths and URLs derived
#: from a network response are checked against these before use, so a
#: compromised or spoofed catalogue response cannot redirect the client at
#: an internal address (SSRF) or an attacker-controlled host.
API_HOST = "api.github.com"
RAW_HOST = "raw.githubusercontent.com"

#: Definition paths are `image/<name>/<variant>/<file>.yaml` and nothing
#: else. Anchored, no dots in components, so `..` cannot appear and a
#: response cannot walk out of the `image/` subtree.
_DEFINITION_PATH = re.compile(
    r"^image/(?P<image>[a-z0-9][a-z0-9_-]{0,63})/"
    r"(?P<variant>[a-z0-9][a-z0-9._-]{0,63})/"
    r"(?P<file>[a-z0-9][a-z0-9._-]{0,63})\.ya?ml$"
)

#: Queries arrive from the command line; only names that could name a
#: catalogue directory are looked up, and the lookup is a dict hit either
#: way, so this is a cheap guard against a query being used to build a URL.
_IMAGE_QUERY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

#: The tree response is bounded before parsing: an unbounded body from a
#: hostile endpoint must not become unbounded memory. The real catalogue
#: tree is around 2 MB.
MAX_TREE_BYTES = 32 * 1024 * 1024

#: GitHub's anonymous budget is 60 requests/hour. This client makes at most
#: one API request per TTL in the normal case; the limiter exists so a cold
#: cache with several concurrent queries cannot burst past the budget.
API_RATE = 10
API_PERIOD = 60.0


class IndexState(StrEnum):
    """How much of the catalogue the current index actually describes.

    Without this, `variants()` returning `{}` meant three different things
    with one shape: the catalogue has no such image, the catalogue could not
    be reached, and the catalogue answered with a tree GitHub had truncated.
    Only the first is a fact about the image. The other two are absences of
    an answer, and a caller that cannot tell them apart reports "DHI has no
    hardened build of this" when what happened was that nobody asked.

    Nothing here changes what the client returns -- discovery still degrades
    to no candidates rather than failing the run. What it changes is that
    the *reason* survives the degradation instead of being flattened into
    an empty dict.
    """

    #: Not loaded yet. No query has been answered from it.
    NOT_LOADED = "NOT_LOADED"
    #: Loaded, and it describes the whole catalogue.
    COMPLETE = "COMPLETE"
    #: GitHub truncated the tree. The index is real and it is short: images
    #: it does not name may still exist in the catalogue.
    TRUNCATED = "TRUNCATED"
    #: The catalogue could not be read at all. Every answer from it is an
    #: absence, and none of them is a statement about any image.
    UNAVAILABLE = "UNAVAILABLE"

    @property
    def is_conclusive(self) -> bool:
        """Whether "no variants" from this index means "the catalogue has none"."""
        return self is IndexState.COMPLETE


class DHICatalogClient:
    """Fetches and caches the DHI catalogue index and its definition files."""

    def __init__(
        self,
        timeout: int = 30,
        cache: CacheStoreInterface | None = None,
        ttl_seconds: int = 21600,
        token: str = "",  # nosec B107 - empty means "anonymous", not a password
        max_definition_bytes: int = 1024 * 1024,
    ):
        self._timeout = timeout
        self._cache = cache
        self._ttl = ttl_seconds
        self._token = token
        self._max_definition_bytes = max_definition_bytes
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()
        self._index: dict[str, dict[str, list[str]]] | None = None
        self._index_lock = asyncio.Lock()
        self._index_state = IndexState.NOT_LOADED
        self._revision: str = ""
        self._limiter = RateLimiter(rate=API_RATE, period=API_PERIOD, burst=API_RATE)
        self._breaker = CircuitBreaker()
        # Definitions fetched in this run, so ten candidates from one image
        # never re-download the same YAML.
        self._definitions: dict[str, DeclaredImageMetadata | None] = {}

    @property
    def revision(self) -> str:
        """Catalogue commit the current index describes, if known.

        Carried into the evidence trail: "DHI said X" is only auditable if
        the reader can tell *which* version of the catalogue said it.
        """
        return self._revision

    @property
    def index_state(self) -> IndexState:
        """Whether an empty answer from this client is a fact or an absence.

        `variants()` returns `{}` for "the catalogue has no such image" and
        for "the catalogue could not be read", and the caller has to be able
        to tell those apart before it says anything about the image.
        """
        return self._index_state

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    headers = {
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    }
                    if self._token:
                        # Never logged: the header is set on the client and
                        # the token itself is not interpolated anywhere else.
                        headers["Authorization"] = f"Bearer {self._token}"
                    self._client = httpx.AsyncClient(
                        timeout=self._timeout,
                        headers=headers,
                        # Redirects are not followed: a redirect is exactly
                        # how a response would move this client off the two
                        # hosts it is allowed to reach.
                        follow_redirects=False,
                    )
        return self._client

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def variants(self, image: str) -> dict[str, list[str]]:
        """Variant directories and definition files the catalogue has for `image`.

        Returns an empty mapping when the catalogue has no such image, when
        the index could not be loaded, or when the query is not a plausible
        catalogue name. An empty mapping means "no DHI candidates", which is
        a fact about discovery -- never a security statement.
        """
        name = image.strip().lower()
        if not _IMAGE_QUERY.match(name):
            return {}
        index = await self._load_index()
        return dict(index.get(name, {}))

    async def definition(self, path: str) -> DeclaredImageMetadata | None:
        """Fetch and parse one definition file by its catalogue path.

        The path is re-validated here rather than trusted from the index,
        because this is the method that turns a string into a URL.
        """
        if not _DEFINITION_PATH.match(path):
            logger.warning(f"Refusing to fetch DHI definition at unexpected path: {path!r}")
            return None
        if path in self._definitions:
            return self._definitions[path]

        parsed = await self._fetch_definition(path)
        self._definitions[path] = parsed
        return parsed

    async def _fetch_definition(self, path: str) -> DeclaredImageMetadata | None:
        cache_key = f"dhi:def:{self._revision or 'head'}:{path}"
        raw = await self._cached_text(cache_key)
        if raw is None:
            url = f"https://{RAW_HOST}/{CATALOG_OWNER}/{CATALOG_REPO}/{CATALOG_BRANCH}/{path}"
            raw = await self._get_text(url, max_bytes=self._max_definition_bytes)
            if raw is None:
                return None
            await self._store_text(cache_key, raw)

        try:
            data = safe_load_yaml(raw, origin=path)
        except UnsafeYAMLError as e:
            # A definition that cannot be read safely yields no candidate.
            # It must never yield a candidate with default values, which
            # would read downstream as a fully-specified hardened image.
            logger.warning(f"Discarding DHI definition {path}: {e}")
            return None
        return parse_definition(data, definition_url=self._definition_url(path))

    @staticmethod
    def _definition_url(path: str) -> str:
        return f"https://github.com/{CATALOG_OWNER}/{CATALOG_REPO}/blob/{CATALOG_BRANCH}/{path}"

    async def _load_index(self) -> dict[str, dict[str, list[str]]]:
        if self._index is not None:
            return self._index
        async with self._index_lock:
            if self._index is not None:
                return self._index
            self._index = await self._resolve_index()
            return self._index

    async def _resolve_index(self) -> dict[str, dict[str, list[str]]]:
        cached = await self._cached_index()
        if cached is not None:
            return cached
        fetched = await self._fetch_index()
        if fetched is None:
            # An unreachable catalogue contributes nothing. Memoised as an
            # empty index so a run with ten queries makes one failed attempt
            # rather than ten -- but memoised *as unavailable*, so the empty
            # dict is never read back as "the catalogue has no such image".
            self._index_state = IndexState.UNAVAILABLE
            logger.warning(
                "DHI catalogue could not be read: this run reports no hardened "
                "candidates from it, which is an absence of an answer and not a "
                "statement that none exist"
            )
            return {}
        index, revision, truncated = fetched
        self._index_state = IndexState.TRUNCATED if truncated else IndexState.COMPLETE
        self._revision = revision
        await self._store_index(index, revision)
        return index

    async def _cached_index(self) -> dict[str, dict[str, list[str]]] | None:
        if self._cache is None:
            return None
        try:
            payload = await self._cache.get("dhi:index")
        except Exception as e:
            logger.warning(f"Could not read the cached DHI catalogue index: {e}")
            return None
        if not isinstance(payload, dict):
            return None
        index = payload.get("index")
        revision = payload.get("revision")
        if not isinstance(index, dict) or not isinstance(revision, str):
            # A corrupted or older-shaped entry is a miss, never a partial
            # index that would silently narrow discovery.
            logger.warning("Discarding malformed DHI catalogue index from cache")
            return None
        cleaned = _validated_index(index)
        if cleaned is None:
            logger.warning("Discarding DHI catalogue index from cache: unexpected paths")
            return None
        self._revision = revision
        self._index_state = IndexState.COMPLETE
        logger.info(f"DHI catalogue index served from cache ({len(cleaned)} images, @{revision})")
        return cleaned

    async def _store_index(self, index: dict[str, dict[str, list[str]]], revision: str) -> None:
        if self._cache is None:
            return
        try:
            await self._cache.set(
                "dhi:index", {"index": index, "revision": revision}, ttl_seconds=self._ttl
            )
        except Exception as e:
            logger.warning(f"Could not cache the DHI catalogue index: {e}")

    async def _fetch_index(self) -> tuple[dict[str, dict[str, list[str]]], str, bool] | None:
        """One API call: the recursive tree, reduced to definition paths.

        Returns `(index, revision, truncated)`, or None when the catalogue
        could not be read. `truncated` travels with the index because a
        short index and a complete one are not the same answer, and the
        difference used to end at a log line.
        """
        url = (
            f"https://{API_HOST}/repos/{CATALOG_OWNER}/{CATALOG_REPO}"
            f"/git/trees/{CATALOG_BRANCH}?recursive=1"
        )
        raw = await self._get_text(url, max_bytes=MAX_TREE_BYTES, api=True)
        if raw is None:
            return None
        try:
            payload: Any = json.loads(raw)
        except ValueError as e:
            logger.warning(f"DHI catalogue tree was not valid JSON: {e}")
            return None
        if not isinstance(payload, dict):
            return None
        truncated = payload.get("truncated") is True
        if truncated:
            # GitHub truncates very large trees. A truncated tree silently
            # hides images, so the fact travels with the index (see
            # `IndexState.TRUNCATED`) rather than only into a log line that
            # nothing downstream reads.
            logger.warning("DHI catalogue tree came back truncated; discovery may be incomplete")

        index: dict[str, dict[str, list[str]]] = {}
        entries = payload.get("tree")
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") != "blob":
                continue
            path = entry.get("path")
            if not isinstance(path, str):
                continue
            match = _DEFINITION_PATH.match(path)
            if not match:
                continue
            index.setdefault(match["image"], {}).setdefault(match["variant"], []).append(path)

        revision = str(payload.get("sha") or "")[:40]
        logger.info(f"DHI catalogue index built: {len(index)} images (@{revision or 'unknown'})")
        return index, revision, truncated

    async def _get_text(self, url: str, *, max_bytes: int, api: bool = False) -> str | None:
        """GET `url` under the rate limiter, breaker and a size bound.

        Returns None for every failure mode -- unreachable, refused,
        oversized, non-2xx. The caller turns that into "no candidates from
        this source", which is the only honest reading.
        """
        provider = "GitHub API" if api else "GitHub raw content"
        try:
            self._breaker.check(provider)
        except CircuitOpenError as e:
            logger.warning(str(e))
            return None

        if api:
            await self._limiter.acquire()

        try:
            client = await self._get_client()
            resp = await client.get(url)
        except httpx.HTTPError as e:
            self._breaker.record_failure()
            logger.warning(f"{provider} request failed: {e}")
            return None

        if resp.status_code in (403, 429):
            # Rate limited or forbidden. Both are budget problems, and both
            # get worse if the client keeps trying.
            self._breaker.record_failure()
            logger.warning(
                f"{provider} refused the request ({resp.status_code}); "
                "set DOCKERLS_GITHUB_TOKEN to raise the anonymous rate limit"
            )
            return None
        if resp.status_code == 404:
            self._breaker.record_success()
            return None
        if not resp.is_success:
            self._breaker.record_failure()
            logger.warning(f"{provider} answered {resp.status_code} for a catalogue request")
            return None

        content = resp.content
        if len(content) > max_bytes:
            self._breaker.record_failure()
            logger.warning(f"{provider} response exceeded {max_bytes} bytes; discarded")
            return None

        self._breaker.record_success()
        return content.decode("utf-8", errors="replace")

    async def _cached_text(self, key: str) -> str | None:
        if self._cache is None:
            return None
        try:
            value = await self._cache.get(key)
        except Exception as e:
            logger.warning(f"Could not read cached DHI definition: {e}")
            return None
        return value if isinstance(value, str) else None

    async def _store_text(self, key: str, value: str) -> None:
        if self._cache is None:
            return
        try:
            await self._cache.set(key, value, ttl_seconds=self._ttl)
        except Exception as e:
            logger.warning(f"Could not cache DHI definition: {e}")


def _validated_index(index: dict[str, Any]) -> dict[str, dict[str, list[str]]] | None:
    """Re-validate an index loaded from the cache.

    The cache is a file on disk that other processes can write. An entry
    whose paths do not match the expected shape is rejected outright rather
    than filtered, because a partially-valid index is indistinguishable
    from a tampered one and would quietly change what gets recommended.
    """
    cleaned: dict[str, dict[str, list[str]]] = {}
    for image, variants in index.items():
        if not isinstance(image, str) or not _IMAGE_QUERY.match(image):
            return None
        if not isinstance(variants, dict):
            return None
        for variant, paths in variants.items():
            if not isinstance(variant, str) or not isinstance(paths, list):
                return None
            for path in paths:
                if not isinstance(path, str) or not _DEFINITION_PATH.match(path):
                    return None
            cleaned.setdefault(image, {})[variant] = list(paths)
    return cleaned
