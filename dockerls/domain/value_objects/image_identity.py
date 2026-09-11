"""Canonical, immutable identity for security evidence.

Tags are discovery metadata, not identities.  This value object deliberately
cannot be built without a valid OCI digest so callers cannot accidentally turn
``latest`` into a cache key that survives a tag mutation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dockerls.domain.value_objects.image_reference import is_registry_host

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_PLATFORM_PART = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
DOCKER_HUB_REGISTRY = "docker.io"


@dataclass(frozen=True, slots=True)
class ImageIdentity:
    """Content-addressed image identity, including the selected platform."""

    registry: str
    repository: str
    digest: str
    platform: str

    def __post_init__(self) -> None:
        if not self.registry or not self.repository:
            raise ValueError("registry and repository are required")
        if not _DIGEST.fullmatch(self.digest):
            raise ValueError("a canonical sha256 OCI digest is required")
        parts = self.platform.split("/")
        if len(parts) not in (2, 3) or any(not _PLATFORM_PART.fullmatch(p) for p in parts):
            raise ValueError("platform must be os/architecture[/variant]")

    @classmethod
    def from_image(cls, image: DockerImage) -> ImageIdentity:
        """Build a strict identity, raising when external metadata is invalid."""
        name = image.name.lower()
        parts = name.split("/")
        if len(parts) > 1 and is_registry_host(parts[0]):
            registry = parts.pop(0)
        else:
            registry = DOCKER_HUB_REGISTRY
        repository = "/".join(parts)
        if registry in {"index.docker.io", "registry-1.docker.io"}:
            registry = DOCKER_HUB_REGISTRY
        if registry == DOCKER_HUB_REGISTRY and "/" not in repository:
            repository = f"library/{repository}"
        platform = f"{image.os}/{image.architecture}".lower()
        return cls(
            registry=registry,
            repository=repository,
            digest=image.digest.lower(),
            platform=platform,
        )

    @classmethod
    def try_from_image(cls, image: DockerImage) -> ImageIdentity | None:
        """Return no identity when untrusted image metadata is not canonical.

        Registry and catalogue responses are untrusted. Callers that use an
        identity only as an optimisation (for example, a cache) must not turn
        malformed metadata into an analysis failure; they skip that
        optimisation and keep the real scan path instead.
        """
        try:
            return cls.from_image(image)
        except ValueError:
            return None

    @property
    def cache_material(self) -> str:
        """Stable, tag-free material suitable for namespaced cache keys."""
        return f"{self.registry}/{self.repository}@{self.digest}#{self.platform}"
