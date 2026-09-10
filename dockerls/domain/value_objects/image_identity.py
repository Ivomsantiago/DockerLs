"""Canonical, immutable identity for security evidence.

Tags are discovery metadata, not identities.  This value object deliberately
cannot be built without a valid OCI digest so callers cannot accidentally turn
``latest`` into a cache key that survives a tag mutation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from dockerls.domain.value_objects.image_reference import is_registry_host

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
    def from_image(cls, image: object) -> ImageIdentity:
        """Build from a DockerImage-like object without importing entities."""
        name = str(getattr(image, "name", "")).lower()
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
        platform = f"{getattr(image, 'os', '')}/{getattr(image, 'architecture', '')}".lower()
        return cls(
            registry=registry,
            repository=repository,
            digest=str(getattr(image, "digest", "")).lower(),
            platform=platform,
        )

    @property
    def cache_material(self) -> str:
        """Stable, tag-free material suitable for namespaced cache keys."""
        return f"{self.registry}/{self.repository}@{self.digest}#{self.platform}"
