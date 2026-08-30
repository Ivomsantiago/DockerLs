"""The current stable versions of a runtime or OS, read from the registry.

`RUNTIME_BASES` in `base_recipe.py` hardcodes one version per (runtime,
family) -- Alpine 3.21, Node 22, Python 3.12 -- and that stays the default
when nobody asks for anything else. This module answers a narrower
question for `--os-version`/`--runtime-version`: what versions actually
exist right now, so a menu can offer "the two latest" without a number
baked into this file going stale the day a project ships its next release.

Nothing here decides which version is *safer* -- that is still `recommend`
and a real scan's job. This only says what is published.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dockerls.domain.value_objects.base_recipe import OsFamily, Runtime
from dockerls.integrations.dockerhub.client import DockerHubClient

if TYPE_CHECKING:
    from collections.abc import Sequence

#: Which Docker Hub repository names this (runtime, family), and the tag
#: shape that names a *stable* release in that family -- one capture group,
#: the version. `python:3.13-rc-alpine` and `node:22-alpine3.20-slim` do not
#: match: a release candidate or a variant tag is not what "the latest
#: stable version" means here.
_SOURCES: dict[tuple[Runtime, OsFamily], tuple[str, re.Pattern[str]]] = {
    (Runtime.NONE, OsFamily.ALPINE): ("alpine", re.compile(r"^(\d+\.\d+)$")),
    (Runtime.NONE, OsFamily.DEBIAN): ("debian", re.compile(r"^(\d+)-slim$")),
    (Runtime.NONE, OsFamily.UBUNTU): ("ubuntu", re.compile(r"^(\d+\.\d+)$")),
    (Runtime.JAVA, OsFamily.ALPINE): ("eclipse-temurin", re.compile(r"^(\d+)-jre-alpine$")),
    (Runtime.JAVA, OsFamily.DEBIAN): ("eclipse-temurin", re.compile(r"^(\d+)-jre$")),
    (Runtime.JAVA, OsFamily.UBUNTU): ("eclipse-temurin", re.compile(r"^(\d+)-jre-noble$")),
    (Runtime.NODE, OsFamily.ALPINE): ("node", re.compile(r"^(\d+)-alpine$")),
    (Runtime.NODE, OsFamily.DEBIAN): ("node", re.compile(r"^(\d+)-slim$")),
    (Runtime.PYTHON, OsFamily.ALPINE): ("python", re.compile(r"^(\d+\.\d+)-alpine$")),
    (Runtime.PYTHON, OsFamily.DEBIAN): ("python", re.compile(r"^(\d+\.\d+)-slim-bookworm$")),
    (Runtime.GO, OsFamily.ALPINE): ("golang", re.compile(r"^(\d+\.\d+)-alpine$")),
    (Runtime.GO, OsFamily.DEBIAN): ("golang", re.compile(r"^(\d+\.\d+)-bookworm$")),
    (Runtime.RUBY, OsFamily.ALPINE): ("ruby", re.compile(r"^(\d+\.\d+)-alpine$")),
    (Runtime.RUBY, OsFamily.DEBIAN): ("ruby", re.compile(r"^(\d+\.\d+)-slim-bookworm$")),
    (Runtime.PHP, OsFamily.ALPINE): ("php", re.compile(r"^(\d+\.\d+)-cli-alpine$")),
    (Runtime.PHP, OsFamily.DEBIAN): ("php", re.compile(r"^(\d+\.\d+)-cli-bookworm$")),
}


@dataclass(frozen=True)
class VersionChoice:
    """One version this (runtime, family) can be pinned to, and the tag it
    resolves to today."""

    version: str
    tag: str


def supports_version_discovery(runtime: Runtime, family: OsFamily) -> bool:
    return (runtime, family) in _SOURCES


def _sort_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


async def discover_versions(
    runtime: Runtime,
    family: OsFamily,
    *,
    count: int = 2,
    client: DockerHubClient | None = None,
) -> Sequence[VersionChoice]:
    """The `count` newest stable versions published for this combination,
    newest first.

    Returns an empty sequence -- never raises -- when the registry cannot
    be reached or this combination has no known tag shape: an empty result
    is "could not measure this", and the caller falls back to the catalog
    default rather than being handed a guess dressed up as one.
    """
    source = _SOURCES.get((runtime, family))
    if source is None:
        return ()
    repository, pattern = source

    owns_client = client is None
    client = client or DockerHubClient()
    try:
        # `search_tags` already degrades to a partial (or empty) result on
        # any HTTP error instead of raising -- there is nothing further to
        # catch here.
        tags = await client.search_tags(repository, limit=100)
    finally:
        if owns_client:
            await client.close()

    by_version: dict[str, str] = {}
    for image in tags:
        match = pattern.match(image.tag)
        if not match:
            continue
        version = match.group(1)
        by_version.setdefault(version, image.tag)

    ordered = sorted(by_version, key=_sort_key, reverse=True)
    return [VersionChoice(version=v, tag=by_version[v]) for v in ordered[:count]]
