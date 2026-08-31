from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.integrations.registry.oci import OCIRegistryClient, is_runnable_tag
from dockerls.utils.retry import DEFAULT_BACKOFF_BASE, DEFAULT_MAX_ATTEMPTS

if TYPE_CHECKING:
    from dockerls.infrastructure.network.host_guard import HostGuard

CHAINGUARD = "Chainguard"
DISTROLESS = "Distroless"


class HardenedRepository(ImageRepositoryInterface):
    """Base for free, security-hardened image sources exposed over the OCI
    Distribution API.

    These registries publish tag names only -- no size, no timestamps -- so
    the resulting `DockerImage` carries the minimum the scan pipeline needs
    and leaves the rest unset rather than inventing values.
    """

    source: str = ""
    host: str = ""
    namespace: str = ""
    # Query name -> repository names, most current first.
    #
    # This was a 1:1 alias map, and 1:1 was the bug. Distroless keeps its
    # legacy repositories published: `distroless/nodejs` still lists tags
    # `10`, `12` and `14`, and `distroless/java` still lists `11`. Mapping
    # `node` onto that single repository meant this tool answered a request
    # for a hardened alternative with a Node runtime that reached end of life
    # years ago -- an insecure image carrying the tool's own recommendation.
    # The current runtimes live in separate, version-named repositories
    # (`nodejs22-debian12`), which no 1:1 alias could reach.
    #
    # A tuple also fixes the second half: an ecosystem legitimately has more
    # than one hardened image (`jdk` and `jre`), and picking one for the
    # reader is a decision that belongs to whoever knows whether the
    # application compiles at runtime.
    repositories: dict[str, tuple[str, ...]] = {}

    def __init__(
        self,
        timeout: int = 30,
        guard: HostGuard | None = None,
        *,
        username: str = "",
        password: str = "",
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        # `self.host` is a constant of this class, but the hops that follow
        # it -- redirects and the token realm -- are chosen by the far end,
        # so the guard travels with the client here for the same reason it
        # does for a user-supplied registry.
        #
        # `username`/`password` are empty for Chainguard and Distroless --
        # both are anonymous, free-tier catalogues -- and only meaningful
        # for a subclass fronting a registry that actually requires them,
        # like `PrivateRegistryRepository`.
        self._client = OCIRegistryClient(
            self.host,
            timeout=timeout,
            guard=guard,
            username=username,
            password=password,
            max_attempts=max_attempts,
            backoff_base=backoff_base,
        )

    def repositories_for(self, image_name: str) -> list[str]:
        """Every repository of this source that could answer the query.

        Returns an empty list for references that already name a different
        registry, so `dockerls recommend ghcr.io/org/app` never fans out to
        Chainguard.
        """
        name = image_name.strip().strip("/").lower()
        if not name or "/" in name or ":" in name:
            return []
        candidates = self.repositories.get(name, (name,))
        return [f"{self.namespace}/{candidate}" for candidate in candidates]

    def repository_for(self, image_name: str) -> str | None:
        """The single most current repository for the query, or None.

        Kept for the callers that identify a source by one path; discovery
        uses `repositories_for`, which is what reaches the version-named
        repositories the legacy alias could not.
        """
        candidates = self.repositories_for(image_name)
        return candidates[0] if candidates else None

    def _full_name(self, repository: str) -> str:
        return f"{self.host}/{repository}"

    def _build_image(self, repository: str, tag: str, payload: dict[str, Any]) -> DockerImage:
        return DockerImage(
            name=self._full_name(repository),
            tag=tag,
            source=self.source,
            is_official=True,
        )

    def _runnable_tags(self, payload: dict[str, Any]) -> list[str]:
        return [t for t in (payload.get("tags") or []) if is_runnable_tag(t)]

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        """Every runnable tag this source offers for the query.

        Each candidate repository is listed in order and the results are
        concatenated, so the current runtime (`nodejs22-debian12`) is offered
        ahead of the legacy one and a source that publishes both a JDK and a
        JRE offers both instead of silently choosing.

        A repository that does not exist is not an error: the candidate lists
        below are per-source guesses about a catalogue that changes on its
        own schedule, and a 404 on one of them must not lose the others.
        """
        images: list[DockerImage] = []
        for repository in self.repositories_for(image_name):
            payload = await self._client.list_tags(repository)
            if payload is None:
                continue
            # Build first, then rank: a source that dates its tags (GCR) must
            # be ordered newest-first, or a lexical sort surfaces nodejs:10
            # ahead of nodejs:22 and the tool recommends a years-old runtime.
            found = [
                self._build_image(repository, tag, payload) for tag in self._runnable_tags(payload)
            ]
            found.sort(key=_image_rank)
            images.extend(found)
            if len(images) >= limit:
                break

        selected = images[:limit]
        logger.info(f"{self.source}: {len(selected)} usable tags for {image_name}")
        return selected

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        repository = self.repository_for(image_name)
        if repository is None:
            return None
        payload = await self._client.list_tags(repository)
        if payload is None or tag not in (payload.get("tags") or []):
            return None
        return self._build_image(repository, tag, payload)

    async def tag_exists(self, image_name: str, tag: str) -> bool | None:
        """A tag returned by a live listing is confirmed by construction.

        The listing is memoised by `OCIRegistryClient`, so verifying ten
        candidates against this source costs the one request discovery
        already made rather than ten more.
        """
        repository = self.repository_for(image_name)
        if repository is None:
            return None
        payload = await self._client.list_tags(repository)
        if payload is None:
            return None
        return tag in (payload.get("tags") or [])

    async def close(self) -> None:
        """Release the shared HTTP connection pool."""
        await self._client.close()


_PREFERRED_TAGS = ("latest", "latest-dev", "nonroot", "debug", "static")


def _image_rank(image: DockerImage) -> tuple[int, str, float, str]:
    """Order: conventional entrypoints first, then newest published, then
    name. Undated tags fall back to name ordering rather than pretending to
    be either new or old."""
    if image.tag in _PREFERRED_TAGS:
        return (0, f"{_PREFERRED_TAGS.index(image.tag):02d}", 0.0, image.tag)
    published = -image.last_updated.timestamp() if image.last_updated else 0.0
    return (1, "", published, image.tag)


class ChainguardRepository(HardenedRepository):
    """Chainguard's free tier (cgr.dev/chainguard/<image>).

    The free catalogue tracks only the moving tags -- `latest`,
    `latest-dev` and friends; pinned version tags are a paid feature -- so a
    handful of results here is the expected outcome, not a failure.
    """

    source = CHAINGUARD
    host = "cgr.dev"
    namespace = "chainguard"
    #: Verificado contra o registry em 2026-08-18: `chainguard/java` não
    #: existe (responde 403 no token endpoint), então quem digitava `java`
    #: recebia zero alternativas. As imagens reais são `jdk` e `jre`, e as
    #: duas são oferecidas porque a escolha depende de a aplicação compilar
    #: em runtime -- não é decisão de quem escaneia.
    repositories = {
        "node": ("node",),
        "nodejs": ("node",),
        "python": ("python",),
        "python3": ("python",),
        "go": ("go",),
        "golang": ("go",),
        "java": ("jdk", "jre"),
        "openjdk": ("jdk", "jre"),
        "temurin": ("jdk", "jre"),
        "corretto": ("jdk", "jre"),
        "jdk": ("jdk",),
        "jre": ("jre",),
        "maven": ("maven",),
        "gradle": ("gradle",),
    }


class DistrolessRepository(HardenedRepository):
    """Google's Distroless images (gcr.io/distroless/<image>)."""

    source = DISTROLESS
    host = "gcr.io"
    namespace = "distroless"
    #: Verificado contra o registry em 2026-08-18. Os repositórios sem sufixo
    #: de versão continuam publicados e **são legado**: `distroless/nodejs`
    #: lista `10`, `12` e `14`, e `distroless/java` lista `11`. Eles ficam de
    #: fora: recomendar um runtime que morreu anos atrás, com o carimbo desta
    #: ferramenta, é pior do que não recomendar nada. Os nomes versionados
    #: também respondem à outra metade do problema -- `nodejs22-debian12` diz
    #: o que é; `nodejs` não dizia.
    repositories = {
        "node": ("nodejs22-debian12", "nodejs20-debian12"),
        "nodejs": ("nodejs22-debian12", "nodejs20-debian12"),
        "python": ("python3-debian12",),
        "python3": ("python3-debian12",),
        # Go compila estático: a imagem de execução não carrega runtime algum.
        "go": ("static-debian12", "base-debian12"),
        "golang": ("static-debian12", "base-debian12"),
        "java": ("java21-debian12", "java17-debian12"),
        "openjdk": ("java21-debian12", "java17-debian12"),
        "temurin": ("java21-debian12", "java17-debian12"),
        "corretto": ("java21-debian12", "java17-debian12"),
        "jdk": ("java21-debian12", "java17-debian12"),
        # O Distroless não publica ferramenta de build: maven e gradle rodam
        # no stage de build, não no de execução. Declarado como ausência em
        # vez de mapeado para algo parecido.
        "maven": (),
        "gradle": (),
    }

    def _build_image(self, repository: str, tag: str, payload: dict[str, Any]) -> DockerImage:
        image = super()._build_image(repository, tag, payload)
        # GCR uniquely returns a manifest map with upload timestamps and
        # sizes, so distroless images can be dated instead of guessed at.
        meta = _gcr_manifest_for_tag(payload, tag)
        if not meta:
            return image
        dated: DockerImage = image.model_copy(update=meta)
        return dated


def _gcr_manifest_for_tag(payload: dict[str, Any], tag: str) -> dict[str, Any]:
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        return {}
    for digest, entry in manifest.items():
        if not isinstance(entry, dict) or tag not in (entry.get("tag") or []):
            continue
        update: dict[str, Any] = {"digest": digest}
        size = entry.get("imageSizeBytes")
        if size is not None:
            with_int = _safe_int(size)
            if with_int is not None:
                update["size_bytes"] = with_int
        uploaded = _safe_int(entry.get("timeUploadedMs"))
        # GCR reports a sentinel far-past timeCreatedMs for many images;
        # timeUploadedMs is the field that reflects reality.
        if uploaded and uploaded > 0:
            update["last_updated"] = datetime.fromtimestamp(uploaded / 1000, tz=UTC)
        return update
    return {}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
