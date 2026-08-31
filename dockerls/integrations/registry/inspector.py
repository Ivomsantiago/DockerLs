"""Resolve a tag to a digest and read the image's configuration.

This is where "digest-first" stops being a slogan. A tag is a mutable
pointer: `node:22` names different bytes this week than last, so a
recommendation that says only `node:22` cannot be checked against the scan
that produced it. Resolving the tag through the registry gives the manifest
digest -- the content-addressed identity of the image -- and everything
downstream (deduplication, caching, the evidence trail, the recommendation
itself) keys off that instead.

The same round-trip yields the OCI image **config**, which is the only
source of verified runtime facts available without pulling and unpacking
the image: the account it runs as, the ports it declares, its entrypoint,
its layer count. Those facts are what the hardening and attack-surface
models are built from, and they are labelled `REGISTRY` because they were
measured, not claimed.

Integrity is checked rather than assumed: a config blob is addressed by its
own SHA-256, so the bytes that come back are hashed and compared against the
digest that was requested. A registry, proxy or cache that returns different
content fails that comparison and the config is discarded. This is a cheap,
real supply-chain check, and skipping it would mean trusting a network path
to describe the image whose security we are about to certify.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.integrations.registry.oci import OCIRegistryClient
from dockerls.utils.retry import DEFAULT_BACKOFF_BASE, DEFAULT_MAX_ATTEMPTS

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage

#: Docker Hub's registry endpoint. Distinct from `hub.docker.com`, which is
#: the catalogue API the search client uses.
DOCKER_HUB_REGISTRY = "registry-1.docker.io"

#: Media types accepted when asking for a manifest. Both the OCI and the
#: Docker v2 spellings, indexes first, because a multi-arch tag answers with
#: an index and the per-architecture manifest has to be selected from it.
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

#: Architecture preferred when a tag resolves to a multi-arch index.
DEFAULT_ARCHITECTURE = "amd64"
DEFAULT_OS = "linux"

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
#: Registry host: a DNS name with an optional port. Anchored, and no
#: userinfo, scheme or path can survive it -- this string is interpolated
#: into a URL, so nothing that could redirect the request is allowed
#: through.
_HOST = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?(:\d{1,5})?$")
_REPOSITORY = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$")


class RegistryInspector:
    """Resolves references to digests and reads image configs, per registry.

    One `OCIRegistryClient` is kept per host so connections and anonymous
    tokens are reused across every candidate from that registry, and each
    (repository, reference) pair is resolved at most once per run.
    """

    def __init__(
        self,
        timeout: int = 30,
        guard: HostGuard | None = None,
        credentials: dict[str, tuple[str, str]] | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        # Where this inspector is permitted to send a request. A reference is
        # user input carrying a hostname, so without a policy `dockerls
        # analyze 169.254.169.254/x` is an outbound request to the cloud
        # metadata endpoint chosen by whoever supplied the reference.
        self._guard = guard or HostGuard()
        # host -> (username, password), for a reference naming a registry
        # this run has credentials for -- the configured private registry,
        # today. `analyze`/`compare`/`alternatives` take a reference
        # directly rather than going through `SourceRegistry`, so this is
        # how they reach the same credentials `--source private` uses.
        self._credentials = credentials or {}
        self._clients: dict[str, OCIRegistryClient] = {}
        self._clients_lock = asyncio.Lock()
        self._resolved: dict[str, tuple[str, dict[str, Any] | None]] = {}
        # Digests learned from a cheap HEAD, kept separately so a later full
        # inspection of the same reference does not re-resolve them.
        self._digests: dict[str, str] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def _client(self, host: str) -> OCIRegistryClient | None:
        if not _HOST.match(host):
            logger.warning(f"Refusing to contact registry with unexpected host: {host!r}")
            return None
        # Checked here rather than at the call sites: this is the single
        # place a host becomes a connection, so a future caller cannot
        # forget the check.
        if not self._guard.allows(host):
            logger.warning(f"Refusing to contact {host}: {self._guard.explain(host)}")
            return None
        async with self._clients_lock:
            client = self._clients.get(host)
            if client is None:
                username, password = self._credentials.get(host, ("", ""))
                client = OCIRegistryClient(
                    host,
                    timeout=self._timeout,
                    guard=self._guard,
                    username=username,
                    password=password,
                    max_attempts=self._max_attempts,
                    backoff_base=self._backoff_base,
                )
                self._clients[host] = client
            return client

    async def close(self) -> None:
        async with self._clients_lock:
            clients, self._clients = list(self._clients.values()), {}
        for client in clients:
            await client.close()

    async def resolve_digest(self, image: DockerImage) -> str:
        """The manifest digest for `image`, from a single HEAD request.

        This is the cheap half of `inspect`, and it runs over every
        candidate rather than just the finalists: without a digest, two tags
        that name the same bytes look like two different images and are
        scanned twice. One HEAD per unresolved tag buys deduplication across
        *every* source -- `node:22`, `node:22-bookworm` and a hardened
        catalogue's alias of the same manifest collapse into one scan.

        Returns "" when the registry cannot be asked or does not answer,
        which leaves the candidate keyed by its reference as before.
        """
        target = _registry_target(image)
        if target is None:
            return ""
        host, repository = target
        key = f"{host}/{repository}:{image.tag}"

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._digests:
                return self._digests[key]
            client = await self._client(host)
            digest = ""
            if client is not None:
                resp = await client.get(
                    f"{repository}/manifests/{image.tag}", accept=MANIFEST_ACCEPT, head=True
                )
                if resp is not None:
                    digest = _clean_digest(resp.headers.get("Docker-Content-Digest", ""))
            self._digests[key] = digest
            return digest

    async def inspect(self, image: DockerImage) -> tuple[str, HardeningFacts]:
        """Return (digest, facts) for `image`.

        The digest is "" when the registry could not be asked or did not
        answer, and the facts are empty in the same case. Both outcomes mean
        "not determined": the caller keeps whatever it already had and the
        candidate carries UNKNOWNs rather than fabricated defaults.
        """
        target = _registry_target(image)
        if target is None:
            return "", HardeningFacts()
        host, repository = target
        reference = image.digest if _DIGEST.match(image.digest) else image.tag
        key = f"{host}/{repository}:{reference}"

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._resolved:
                digest, config = self._resolved[key]
            else:
                digest, config = await self._resolve(host, repository, reference)
                self._resolved[key] = (digest, config)
                if digest:
                    self._digests.setdefault(f"{host}/{repository}:{image.tag}", digest)

        return digest, _facts_from_config(config)

    async def _resolve(
        self, host: str, repository: str, reference: str
    ) -> tuple[str, dict[str, Any] | None]:
        client = await self._client(host)
        if client is None:
            return "", None

        resp = await client.get(f"{repository}/manifests/{reference}", accept=MANIFEST_ACCEPT)
        if resp is None:
            return "", None

        digest = _clean_digest(resp.headers.get("Docker-Content-Digest", ""))
        try:
            manifest: Any = resp.json()
        except ValueError:
            logger.warning(f"Registry returned an unparseable manifest for {host}/{repository}")
            return digest, None
        if not isinstance(manifest, dict):
            return digest, None

        manifests = manifest.get("manifests")
        if isinstance(manifests, list):
            # A multi-arch index. The index digest is the image's identity,
            # so it is kept; the per-architecture manifest is followed only
            # to reach the config.
            child = _select_platform(manifests)
            if child is None:
                return digest, None
            child_digest = _clean_digest(str(child.get("digest") or ""))
            if not child_digest:
                return digest, None
            child_resp = await client.get(
                f"{repository}/manifests/{child_digest}", accept=MANIFEST_ACCEPT
            )
            if child_resp is None:
                return digest, None
            try:
                manifest = child_resp.json()
            except ValueError:
                return digest, None
            if not isinstance(manifest, dict):
                return digest, None

        config = await self._fetch_config(client, host, repository, manifest)
        return digest, config

    async def _fetch_config(
        self,
        client: OCIRegistryClient,
        host: str,
        repository: str,
        manifest: dict[str, Any],
    ) -> dict[str, Any] | None:
        descriptor = manifest.get("config")
        if not isinstance(descriptor, dict):
            return None
        config_digest = _clean_digest(str(descriptor.get("digest") or ""))
        if not config_digest:
            return None

        resp = await client.get(f"{repository}/blobs/{config_digest}")
        if resp is None:
            return None

        # Content addressing, actually checked. A blob whose bytes do not
        # hash to the digest that named it is not the config this manifest
        # points at, whatever the registry says.
        actual = f"sha256:{hashlib.sha256(resp.content).hexdigest()}"
        if actual != config_digest:
            logger.warning(
                f"Config blob digest mismatch for {host}/{repository}: "
                f"requested {config_digest}, received {actual}. Discarding."
            )
            return None

        try:
            config: Any = json.loads(resp.content)
        except ValueError:
            logger.warning(f"Config blob for {host}/{repository} was not valid JSON")
            return None
        if not isinstance(config, dict):
            return None
        # The layer list lives on the manifest, not the config, and it is
        # what gives a verified layer count.
        layers = manifest.get("layers")
        if isinstance(layers, list):
            config["__layers"] = layers
        return config


def _registry_target(image: DockerImage) -> tuple[str, str] | None:
    """Split an image name into (registry host, repository path).

    Unqualified names are Docker Hub, where a single-component name lives
    under `library/`. Returns None for anything whose host or repository
    does not match the expected shape, so a crafted name cannot become a
    request to an arbitrary URL.
    """
    name = image.name.strip()
    host = image.registry_host
    repository = name[len(host) + 1 :] if host else name
    if not host:
        host = DOCKER_HUB_REGISTRY
        if "/" not in repository:
            repository = f"library/{repository}"

    if not _HOST.match(host) or not _REPOSITORY.match(repository):
        logger.info(f"Not resolving {name!r}: unexpected registry or repository shape")
        return None
    return host, repository


def _select_platform(manifests: list[Any]) -> dict[str, Any] | None:
    """Pick the linux/amd64 entry of an index, or the first usable one.

    Attestation manifests (cosign, SLSA) appear alongside real images in
    modern indexes and declare `platform.architecture: unknown`; selecting
    one would produce a config describing a signature rather than an image.
    """
    usable: list[dict[str, Any]] = []
    for entry in manifests:
        if not isinstance(entry, dict):
            continue
        platform = entry.get("platform")
        platform = platform if isinstance(platform, dict) else {}
        architecture = str(platform.get("architecture") or "")
        if architecture == "unknown":
            continue
        if architecture == DEFAULT_ARCHITECTURE and str(platform.get("os") or "") == DEFAULT_OS:
            return entry
        usable.append(entry)
    return usable[0] if usable else None


def _clean_digest(value: str) -> str:
    digest = value.strip().lower()
    return digest if _DIGEST.match(digest) else ""


def _facts_from_config(config: dict[str, Any] | None) -> HardeningFacts:
    """Turn an OCI image config into verified facts.

    The one judgement call worth stating: an image whose config sets no
    `User` runs as root. That is a determined FALSE for `runs_as_non_root`,
    not an UNKNOWN -- the config was read and it says the default account is
    root. The distinction matters, because "the image does not say" and
    "nobody looked" have opposite consequences for a score.
    """
    if config is None:
        return HardeningFacts()

    section = config.get("config")
    section = section if isinstance(section, dict) else {}

    user = str(section.get("User") or "").strip()
    ports = _ports(section.get("ExposedPorts"))
    entrypoint = _string_list(section.get("Entrypoint"))
    cmd = _string_list(section.get("Cmd"))
    layers = config.get("__layers")
    layer_count = len(layers) if isinstance(layers, list) else None
    size = _total_size(layers) if isinstance(layers, list) else None

    evidence = {
        "runs_as_non_root": EvidenceSource.REGISTRY,
        "exposed_ports": EvidenceSource.REGISTRY,
        "has_healthcheck": EvidenceSource.REGISTRY,
        "entrypoint": EvidenceSource.REGISTRY,
    }
    if layer_count is not None:
        evidence["layer_count"] = EvidenceSource.REGISTRY

    return HardeningFacts(
        runs_as_non_root=Tristate.of(bool(user) and user.split(":", 1)[0] not in ("root", "0")),
        user=user,
        exposed_ports=ports,
        # A config that declares no healthcheck was still read: Docker treats
        # an absent Healthcheck as "none", which is a determined fact.
        has_healthcheck=Tristate.of(bool(section.get("Healthcheck"))),
        entrypoint=entrypoint,
        cmd=cmd,
        layer_count=layer_count,
        size_bytes=size,
        os_family=str(config.get("os") or ""),
        config_verified=True,
        evidence=evidence,
    )


def _ports(value: Any) -> list[int]:
    """Port numbers from an OCI `ExposedPorts` map ("8080/tcp": {})."""
    if not isinstance(value, dict):
        return []
    ports: list[int] = []
    for key in value:
        if not isinstance(key, str):
            continue
        head = key.split("/", 1)[0]
        try:
            port = int(head)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.append(port)
    return sorted(set(ports))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _total_size(layers: list[Any]) -> int | None:
    total = 0
    seen = False
    for layer in layers:
        if not isinstance(layer, dict):
            continue
        size = layer.get("size")
        if isinstance(size, int) and size >= 0:
            total += size
            seen = True
    return total if seen else None
