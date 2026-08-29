"""Docker Hardened Images as an image source.

DHI is different from every other source this tool searches, in a way that
shapes the whole integration: its *catalogue* is public (a GitHub
repository of build definitions) while its *registry* is not (dhi.io refuses
anonymous pulls). Discovery therefore works for everyone; scanning works
only for a machine holding DHI credentials.

That split is not a limitation to work around -- it is the exact case the
rest of this codebase was built to handle honestly. A DHI candidate is
discovered from the catalogue and enters the same pipeline as everything
else. If the registry will not serve it, the scan fails, the candidate is
reported as UNVERIFIED, and it is never ranked, never scored, and never
called production ready. What a vendor says about its own hardening does not
substitute for a measurement, and this provider is where that rule is at its
most tempting to break.

The candidate a definition produces carries the definition's declared
metadata alongside it, so the CLI can explain *why* a DHI image is worth
considering (non-root by declaration, a supported lifecycle, a small package
set) while keeping every one of those claims labelled as a claim.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface

if TYPE_CHECKING:
    from dockerls.domain.entities.declared_metadata import DeclaredImageMetadata
    from dockerls.integrations.dhi.catalog import DHICatalogClient

DHI = "Docker Hardened Images"
DHI_REGISTRY = "dhi.io"

#: Query name -> catalogue directory, where DHI names an image differently
#: from the Docker Hub convention a user types.
ALIASES = {
    "nodejs": "node",
    "python3": "python",
    "golang": "go",
    "openjdk": "jdk",
    "postgresql": "postgres",
}

#: Variant suffixes that are not the image most users want. `-dev` ships a
#: shell, a package manager and a compiler by design; `sfw`/`ent` are the
#: FIPS and enterprise builds, which are not pullable at all without the
#: corresponding entitlement. They are still discoverable by name -- they are
#: just not what a bare `recommend node` should fan out to.
DEPRIORITISED_MARKERS = ("dev", "sfw", "swf", "ent")


class DHIRepository(ImageRepositoryInterface):
    """Discovers candidates from the DHI catalogue's build definitions."""

    source = DHI
    host = DHI_REGISTRY

    def __init__(self, catalog: DHICatalogClient, definition_limit: int = 12):
        self._catalog = catalog
        self._definition_limit = max(1, definition_limit)

    def repository_for(self, image_name: str) -> str | None:
        """Map a user's query onto a catalogue directory name.

        Returns None for anything that already names a registry or a
        namespace: `recommend ghcr.io/org/app` must not fan out to DHI, and
        a slash in the query means the user has already been specific.
        """
        name = image_name.strip().strip("/").lower()
        if not name or "/" in name or ":" in name:
            return None
        return ALIASES.get(name, name)

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        catalogue_name = self.repository_for(image_name)
        if catalogue_name is None:
            return []

        variants = await self._catalog.variants(catalogue_name)
        if not variants:
            # Empty has three causes and only one of them is about the
            # image. Saying which one happened is the difference between
            # "DHI publishes no hardened build of this" and "nobody asked",
            # and the second must not be reported as the first.
            state = self._catalog.index_state
            if state.is_conclusive:
                logger.info(f"{DHI}: the catalogue has no {catalogue_name}")
            else:
                logger.warning(
                    f"{DHI}: no candidates for {catalogue_name}, and the catalogue index "
                    f"is {state} -- this is an absence of an answer, not a finding that "
                    "no hardened build exists"
                )
            return []

        candidates: list[DockerImage] = []
        for path in self._selected_paths(variants):
            declared = await self._catalog.definition(path)
            if declared is None:
                continue
            image = self._build_image(declared)
            if image is None:
                continue
            candidates.append(image)
            if len(candidates) >= limit:
                break

        logger.info(
            f"{DHI}: {len(candidates)} candidate(s) for {catalogue_name} "
            f"(catalogue @{self._catalog.revision or 'unknown'})"
        )
        return candidates

    def _selected_paths(self, variants: dict[str, list[str]]) -> list[str]:
        """Bound and order the definitions this query will read.

        A popular image has dozens of definitions across OS variants and
        build flavours. Fetching all of them would be a request each, so the
        list is ordered -- runtime flavours before `-dev`, newest OS variant
        first, newest version first -- and cut at `definition_limit`. The
        ordering is total and deterministic, so two runs against the same
        catalogue revision read the same files.
        """
        paths = [path for variant_paths in variants.values() for path in variant_paths]
        paths.sort(key=_definition_rank)
        return paths[: self._definition_limit]

    def _build_image(self, declared: DeclaredImageMetadata) -> DockerImage | None:
        """Turn a definition into a candidate pinned to its primary tag.

        A definition publishes a dozen aliases of the same image (`22`,
        `22.23`, `22.23.2-debian13`, ...). They are the same bytes, so
        emitting one candidate per alias would multiply the scan work by
        twelve for no additional information. The most specific tag is
        chosen, because it is the one that stays meaningful over time.
        """
        tag = _primary_tag(declared.tags)
        repository = _repository_name(declared)
        if not tag or not repository:
            return None
        return DockerImage(
            name=repository,
            tag=tag,
            source=DHI,
            os=declared.os_id or "linux",
            available_architectures=[p.split("/")[-1] for p in declared.platforms],
            declared=declared,
        )

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        for image in await self.search_tags(image_name, limit=self._definition_limit):
            if image.tag == tag:
                return image
        return None

    async def tag_exists(self, image_name: str, tag: str) -> bool | None:
        """Whether the *catalogue* declares this tag.

        Deliberately not a registry check: dhi.io refuses anonymous
        requests, so this provider cannot confirm that a tag is actually
        published. Returning True here would mean "the definition says this
        tag exists", which is not what the caller is asking, so a catalogue
        hit answers None -- unknown -- and the tag stands or falls on
        whether the scanner could pull it.
        """
        del image_name, tag
        return None

    async def close(self) -> None:
        await self._catalog.close()


def _repository_name(declared: DeclaredImageMetadata) -> str:
    """The repository a definition publishes to, if it is a DHI repository.

    The definition states it as `image: dhi.io/node`. It is *checked* here
    rather than trusted: a definition that names some other host would
    otherwise let catalogue content redirect a scan at an arbitrary
    registry. Anything that is not a `dhi.io/...` path yields no candidate.
    """
    repository = declared.registry_repository.strip().lower()
    prefix = f"{DHI_REGISTRY}/"
    if not repository.startswith(prefix):
        return ""
    path = repository[len(prefix) :]
    if not path or not _REPOSITORY_PATH.match(path):
        return ""
    return f"{DHI_REGISTRY}/{path}"


_REPOSITORY_PATH = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")


def _primary_tag(tags: tuple[str, ...]) -> str:
    """The most specific tag a definition publishes.

    Specificity is measured by dotted components then by length, so
    `22.23.2-debian13` beats `22`. A pinned tag is the one worth recording
    in a recommendation: `22` moves with every patch release, and a
    recommendation that moves is a recommendation that was never verified.
    """
    if not tags:
        return ""
    return max(tags, key=lambda tag: (tag.count("."), len(tag), tag))


def _definition_rank(path: str) -> tuple[int, str]:
    """Order definitions: plain runtime flavours first, newest variant first.

    The variant directory (`debian-13`, `alpine-3.24`) is reversed so the
    highest version sorts first, and any definition whose file name carries
    a de-prioritised marker sinks below the plain ones.
    """
    parts = path.split("/")
    variant = parts[2] if len(parts) > 3 else ""
    filename = parts[-1].rsplit(".", 1)[0]
    markers = set(filename.lower().replace(".", "-").split("-"))
    deprioritised = 1 if markers & set(DEPRIORITISED_MARKERS) else 0
    # Reverse-lexicographic on variant and file name, achieved by negating
    # the ordering with a descending key built from the strings themselves.
    return (deprioritised, _descending(f"{variant}/{filename}"))


def _descending(value: str) -> str:
    """Key that sorts `value` in reverse order under an ascending sort.

    Inverting each code point keeps the comparison total and stable without
    needing a second sort pass or a reverse=True that would also flip the
    de-prioritisation flag.
    """
    return "".join(chr(0x10FFFF - ord(ch)) for ch in value)
