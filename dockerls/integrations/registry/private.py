"""A private registry, reachable the same way any OCI Distribution V2
registry is: host, optional namespace, and Basic credentials exchanged for
a scoped bearer token at whatever realm the registry's 401 challenge names.

This is deliberately one implementation, not one per vendor. ECR, Harbor,
GHCR's container registry, Artifactory, and a self-hosted `registry:2` all
speak the same protocol -- the only per-registry difference is the host,
namespace, and how the operator obtained a password (`aws ecr
get-login-password` for ECR, a personal access token for GHCR, a robot
account for Harbor). None of that changes what this client sends over the
wire, so none of it needs its own class.

Configured through `Settings` (`DOCKERLS_PRIVATE_REGISTRY_HOST` and
friends) and registered with `SourceRegistry` like every other source --
`recommend`/`search`/`analyze`/`compare` never learn this exists as a
distinct case.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dockerls.integrations.registry.hardened import HardenedRepository

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage
    from dockerls.infrastructure.network.host_guard import HostGuard

PRIVATE_REGISTRY = "Private Registry"


class PrivateRegistryRepository(HardenedRepository):
    """One organization's own registry, authenticated with Basic
    credentials against the standard Docker Registry HTTP API V2 token
    endpoint.

    Unlike Chainguard/Distroless, whose `repositories` map is a small,
    curated alias table for a handful of well-known ecosystem names, a
    private registry's repository names *are* the query: `team/app`,
    `internal/base-images/python`, whatever the organization's own naming
    convention is. Multi-segment paths are accepted rather than refused --
    that refusal in the base class exists to keep Chainguard/Distroless
    from being asked about a reference that already names a different
    registry, which does not apply here since this repository *is* the
    registry the reference is being asked about.
    """

    source = PRIVATE_REGISTRY

    def __init__(
        self,
        host: str,
        namespace: str = "",
        timeout: int = 30,
        guard: HostGuard | None = None,
        *,
        username: str = "",
        password: str = "",
    ):
        self.host = host
        self.namespace = namespace
        super().__init__(timeout=timeout, guard=guard, username=username, password=password)

    def repositories_for(self, image_name: str) -> list[str]:
        name = image_name.strip().strip("/")
        if not name or ":" in name:
            return []
        if self.namespace:
            return [f"{self.namespace}/{name}"]
        return [name]

    def _build_image(self, repository: str, tag: str, payload: dict[str, Any]) -> DockerImage:
        # `is_official=False`: this is an organization's own image, not a
        # vetted upstream catalogue like Docker Hub official images or
        # Chainguard's -- it must not collect the scoring bonus those get.
        # The base class defaults to `is_official=True`, so it is
        # overridden explicitly rather than left to that default.
        image = super()._build_image(repository, tag, payload)
        return image.model_copy(update={"is_official": False})
