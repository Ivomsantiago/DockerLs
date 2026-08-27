from __future__ import annotations

import contextlib
import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from dockerls.domain.value_objects.scan_plan import DEFAULT_SCAN_BUDGET


def _default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "dockerls"
    return Path.home() / ".cache" / "dockerls"


def _default_state_dir() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "dockerls"
    return Path.home() / ".local" / "state" / "dockerls"


def _default_log_dir() -> Path:
    return _default_state_dir() / "logs"


def _default_evidence_dir() -> Path:
    return _default_state_dir() / "scans"


def _default_config_path() -> Path:
    """~/.config/dockerls/config.toml (or $XDG_CONFIG_HOME/dockerls/config.toml)."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "dockerls" / "config.toml"


class Settings(BaseSettings):
    """Configuration resolved, highest priority first, from: constructor
    kwargs -> environment variables -> ~/.config/dockerls/config.toml ->
    field defaults. DOCKERHUB_USERNAME and DOCKERHUB_TOKEN keep
    their historical unprefixed env var names for backward compatibility;
    every other setting is DOCKERLS_<FIELD_NAME>.
    """

    model_config = SettingsConfigDict(
        env_prefix="DOCKERLS_",
        toml_file=_default_config_path(),
        extra="ignore",
    )

    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_seconds: int = 86400
    # Tag existence is cached separately and more briefly: a tag
    # disappearing matters sooner than a score going slightly stale.
    tag_cache_ttl_seconds: int = 6 * 3600
    max_tags: int = 100
    # Quantas das tags descobertas este run realmente mede. `max_tags`
    # governa a *descoberta*; isto governa a *medição*, e são coisas
    # diferentes: descobrir 100 tags custa uma chamada HTTP, medir as 100
    # custa dois a quatro minutos de Trivy para exibir cinco.
    #
    # O corte não esconde nada. As tags não medidas voltam no resultado
    # (`deferred`) com o motivo -- quase sempre "existe uma tag mais nova
    # da mesma linha" --, porque uma tag não medida não é uma tag pior.
    # `0` mede todas, que é o comportamento anterior.
    scan_budget: int = DEFAULT_SCAN_BUDGET
    # 0 means "derive from this machine": each worker holds a scanner
    # process that wants a core and hundreds of megabytes, so a flat number
    # oversubscribes small runners and underuses large ones. Any explicit
    # value is honoured as given -- the operator knows their machine.
    workers: int = 0
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 5
    dockerhub_username: str = Field(default="", validation_alias="DOCKERHUB_USERNAME")
    dockerhub_token: str = Field(default="", validation_alias="DOCKERHUB_TOKEN")
    log_level: str = "INFO"
    # Diagnostics go here, never to the terminal (see setup_logging).
    log_dir: Path = Field(default_factory=_default_log_dir)
    # Raw scanner JSON, kept so every displayed score is auditable.
    evidence_dir: Path = Field(default_factory=_default_evidence_dir)
    # Trivy's own cache root; the per-worker cache pool is built next to it.
    trivy_cache_dir: Path | None = None
    # Re-scan the top candidates with the secondary scanner and flag
    # material disagreements instead of showing an undisputed score.
    cross_validate: bool = True
    # Confirm each recommended tag really exists on Docker Hub.
    verify_hub_tags: bool = True
    # Concurrent secondary scans during cross-validation. 0 means "derive
    # from this machine", like `workers`: these are scanner processes too,
    # and five of them on a two-core runner contend for exactly the same
    # cores the primary scan just finished using.
    cross_validate_workers: int = 0
    # Search free hardened catalogues (Chainguard, Distroless) alongside
    # Docker Hub, so a hardened image can win on measured vulnerabilities.
    include_hardened_sources: bool = True
    # Tags pulled per hardened source; these catalogues are small and their
    # listings are unordered, so a wide fetch buys nothing.
    hardened_tag_limit: int = 10
    # Docker Hardened Images. Off by default because dhi.io refuses
    # anonymous pulls: without credentials its candidates cannot be scanned,
    # and an unscannable candidate is reported UNVERIFIED rather than
    # ranked. `--source dhi` turns it on for a single run regardless.
    include_dhi_source: bool = False
    # How long the DHI catalogue index stays usable before it is refetched.
    # The catalogue moves a few times a day; six hours keeps discovery
    # current while costing one GitHub API request per window.
    dhi_catalog_ttl_seconds: int = 6 * 3600
    # Definition files read per DHI query. Each is one CDN request, and a
    # popular image has dozens across OS variants and build flavours.
    dhi_definition_limit: int = 12
    # Raises GitHub's anonymous 60-requests/hour ceiling for catalogue
    # refreshes. Read-only public data: no scope is required.
    github_token: str = Field(default="", validation_alias="DOCKERLS_GITHUB_TOKEN")
    # Resolve every unpinned tag to a manifest digest before scanning. This
    # is what makes deduplication work across sources: without it, tags that
    # share a manifest are scanned once each.
    resolve_digests: bool = True
    # Fetch the OCI config of each finalist to measure how it is configured
    # (non-root, ports, entrypoint) instead of relying on vendor claims.
    inspect_image_config: bool = True
    # Where an image reference is allowed to make this process connect. A
    # reference is user input, so without these a crafted name reaches the
    # cloud metadata endpoint or a service on the runner. Private ranges are
    # allowed by default because internal registries are ordinary; loopback
    # and link-local are not, because that is the actual attack.
    network_allow_private_networks: bool = True
    network_allow_loopback: bool = False
    network_allow_link_local: bool = False
    #: Hosts permitted regardless of where they resolve ("registry:5000").
    network_allowed_hosts: list[str] = Field(default_factory=list)
    scanner_timeout: int = 300
    http_timeout: int = 30
    retry_max_attempts: int = 3
    retry_backoff_base: float = 2.0
    enable_threat_intel: bool = True

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    def model_post_init(self, __context: object) -> None:
        # Legacy opt-out flag from before the DOCKERLS_ env prefix was
        # introduced; keep honoring it alongside DOCKERLS_ENABLE_THREAT_INTEL.
        if os.environ.get("DOCKERLS_DISABLE_THREAT_INTEL"):
            self.enable_threat_intel = False

    @property
    def db_path(self) -> Path:
        return self.cache_dir / "cache.db"

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Log and evidence dirs are best-effort: a read-only working
        # directory must degrade (setup_logging falls back to the cache dir,
        # evidence recording is skipped) rather than abort the command.
        for path in (self.log_dir, self.evidence_dir):
            with contextlib.suppress(OSError):
                path.mkdir(parents=True, exist_ok=True)
