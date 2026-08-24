from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.application.services.composite_repository import CompositeImageRepository
from dockerls.application.services.cross_validation import CrossValidator
from dockerls.application.services.hardening_analysis import HardeningAnalyzer
from dockerls.application.services.scanner_factory import ScannerFactory
from dockerls.application.services.source_registry import SourceRegistry, SourceSpec
from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.domain.entities.image import DOCKER_HUB
from dockerls.domain.value_objects.network_policy import NetworkPolicy
from dockerls.infrastructure.config.settings import Settings
from dockerls.infrastructure.evidence import EvidenceStore
from dockerls.infrastructure.logging.setup import setup_logging
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.integrations.dhi.catalog import DHICatalogClient
from dockerls.integrations.dhi.repository import DHI, DHIRepository
from dockerls.integrations.dockerhub.client import DockerHubClient
from dockerls.integrations.endoflife.checker import EndOfLifeChecker
from dockerls.integrations.exploitdb.client import ExploitDBClient
from dockerls.integrations.registry.hardened import (
    CHAINGUARD,
    DISTROLESS,
    ChainguardRepository,
    DistrolessRepository,
)
from dockerls.integrations.registry.inspector import RegistryInspector
from dockerls.integrations.threat_intel.client import ThreatIntelClient
from dockerls.utils.auth import load_credentials
from dockerls.utils.resources import describe_capacity, recommended_workers
from dockerls.utils.validation import validate_threshold, validate_workers

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from dockerls.application.services.progress import ScanObserver
    from dockerls.application.services.source_registry import SourceBuilder
    from dockerls.cache.sqlite_cache import SQLiteCache
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface

# Populated by _settings() on first use; exposed so commands can tell the
# user exactly which file the run's diagnostics landed in.
_LOG_FILE: Path | None = None


@lru_cache(maxsize=1)
def _settings() -> Settings:
    global _LOG_FILE
    s = Settings()
    s.ensure_dirs()
    _LOG_FILE = setup_logging(s.log_level, log_dir=s.log_dir)
    return s


def current_log_file() -> Path | None:
    _settings()
    return _LOG_FILE


def configure_logging() -> None:
    """Detach loguru's default stderr sink before any command runs.

    Until a sink is configured, loguru logs everything from DEBUG up to
    stderr. Commands that never touched Settings -- `build` was one --
    inherited that default and leaked INFO lines into the terminal.
    """
    _settings()


def enable_console_logging() -> None:
    """Re-attach the stderr sink (``--verbose``) on top of the file sink.

    The stderr sink runs at the configured `log_level` here (INFO by
    default, DEBUG via DOCKERLS_LOG_LEVEL) rather than the WARNING floor
    that applies without ``--verbose``.
    """
    s = _settings()
    global _LOG_FILE
    _LOG_FILE = setup_logging(
        s.log_level, log_dir=s.log_dir, console=True, console_level=s.log_level
    )


def resolve_workers(requested: int | None = None) -> int:
    """How many scanner processes this run may hold at once.

    Precedence: the command line, then the configured value, then the
    machine. `0` in either of the first two means "ask the machine", which
    is the default -- a scanner process is not a coroutine, and ten of them
    on a two-core runner is slower than four, not faster.

    An explicit value above what the machine can carry is honoured and
    logged. Refusing it would be presumptuous: an operator scanning tiny
    images, or one who has measured their own runner, is entitled to
    overcommit. Doing it silently is what must not happen.
    """
    s = _settings()
    configured = requested if requested is not None else s.workers
    recommended = recommended_workers()

    if not configured:
        logger.info(
            f"Using {recommended} scanner worker(s) for this machine "
            f"({describe_capacity()}); set --workers to override"
        )
        return recommended

    effective = validate_workers(configured, "--workers")
    if effective > recommended:
        logger.warning(
            f"{effective} scanner workers requested on a machine with "
            f"{describe_capacity()}; each worker holds a scanner process, so this may "
            f"contend for CPU or memory. {recommended} is what this machine suggests."
        )
    return effective


def resolve_tag_limit(limit: int | None) -> int:
    """`--limit` falls back to the configured `max_tags`."""
    s = _settings()
    return validate_threshold(s.max_tags if limit is None else limit, "--limit")


def build_evidence_store() -> EvidenceStore:
    return EvidenceStore(_settings().evidence_dir)


async def build_repository(cache: SQLiteCache | None = None) -> DockerHubClient:
    s = _settings()
    username = s.dockerhub_username
    token = s.dockerhub_token
    if not username or not token:
        username, token = load_credentials()

    client = DockerHubClient(
        username=username,
        token=token,
        timeout=s.http_timeout,
        cache=cache,
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
        tag_ttl_seconds=s.tag_cache_ttl_seconds,
    )
    if username and token:
        await client.authenticate()
    return client


def build_cache() -> SQLiteCache:
    # Import tardio: `SQLiteCache` puxa o SQLAlchemy, que sozinho responde por
    # cerca de um segundo do arranque do processo. Comandos que nunca tocam o
    # cache -- `version`, `--help`, `controls`, `policy` -- pagavam esse
    # segundo em toda invocação, e um segundo de espera antes de um `--help` é
    # o tipo de coisa que faz uma ferramenta parecer pesada sem ser.
    from dockerls.cache.sqlite_cache import SQLiteCache

    s = _settings()
    return SQLiteCache(s.db_path)


@lru_cache(maxsize=1)
def _threat_intel() -> ThreatIntelClient | None:
    s = _settings()
    if not s.enable_threat_intel:
        return None
    return ThreatIntelClient(timeout=s.http_timeout)


@lru_cache(maxsize=1)
def _exploitdb() -> ExploitDBClient | None:
    """O catálogo do Exploit-DB, atrás da mesma chave que KEV/EPSS.

    Segue `enable_threat_intel` porque responde à mesma pergunta -- quão
    explorável é isto -- e quem desliga o enriquecimento não quer que este
    fique de fora. Ao contrário do `ThreatIntelClient`, recebe o cache em
    disco: o CSV tem cerca de 10 MB, e rebaixá-lo a cada invocação seria
    pagar o download inteiro para reler o mesmo dia de catálogo.
    """
    s = _settings()
    if not s.enable_threat_intel:
        return None
    return ExploitDBClient(timeout=s.http_timeout, cache=build_cache(), guard=build_host_guard())


def build_source_registry(cache: SQLiteCache | None = None) -> SourceRegistry:
    """Every catalogue this build can search, keyed by its `--source` token.

    This is the one place that knows the full set. Commands ask the registry
    to resolve a selection; none of them names a provider, so adding one is
    a `register()` call here and nothing else.
    """
    s = _settings()
    registry = SourceRegistry()
    registry.register(
        SourceSpec(
            name="dockerhub",
            label=DOCKER_HUB,
            build=lambda: build_repository(cache=cache),
            primary=True,
            description="Docker Hub (official and community images)",
        )
    )
    registry.register(
        SourceSpec(
            name="chainguard",
            label=CHAINGUARD,
            build=_source_builder(lambda: ChainguardRepository(timeout=s.http_timeout)),
            default_enabled=s.include_hardened_sources,
            description="Chainguard free tier (cgr.dev)",
        )
    )
    registry.register(
        SourceSpec(
            name="distroless",
            label=DISTROLESS,
            build=_source_builder(lambda: DistrolessRepository(timeout=s.http_timeout)),
            default_enabled=s.include_hardened_sources,
            description="Google Distroless (gcr.io/distroless)",
        )
    )
    registry.register(
        SourceSpec(
            name="dhi",
            label=DHI,
            build=_source_builder(
                lambda: DHIRepository(
                    catalog=DHICatalogClient(
                        timeout=s.http_timeout,
                        cache=cache,
                        ttl_seconds=s.dhi_catalog_ttl_seconds,
                        token=s.github_token,
                    ),
                    definition_limit=s.dhi_definition_limit,
                )
            ),
            # Off unless asked for: dhi.io refuses anonymous pulls, so its
            # candidates cannot be scanned on a machine without Docker
            # Hardened Images credentials, and an unscannable candidate is
            # reported as UNVERIFIED rather than ranked.
            default_enabled=s.include_dhi_source,
            requires_auth=True,
            description="Docker Hardened Images catalog (dhi.io, needs credentials to scan)",
        )
    )
    return registry


def _source_builder(factory: Callable[[], ImageRepositoryInterface]) -> SourceBuilder:
    """Adapt a synchronous constructor to the registry's async builder."""

    async def build() -> ImageRepositoryInterface:
        return factory()

    return build


async def build_composite_repository(specs: list[SourceSpec]) -> CompositeImageRepository:
    """Instantiate the resolved sources and fan a query across them.

    The first spec is the primary and gets the full `--limit`; the rest are
    capped at `hardened_tag_limit`, because a curated catalogue publishes a
    handful of tags where Docker Hub publishes hundreds.
    """
    if not specs:
        raise ValueError("at least one image source must be selected")
    built = [await spec.build() for spec in specs]
    return CompositeImageRepository(built[0], built[1:], extra_limit=_settings().hardened_tag_limit)


async def build_sources(
    selection: Sequence[str] | None = None,
    *,
    all_sources: bool = False,
    include_hardened: bool | None = None,
    cache: SQLiteCache | None = None,
) -> CompositeImageRepository:
    """Resolve a `--source`/`--all-sources` selection into a live repository.

    One entry point for every command, so `search`, `recommend`,
    `alternatives` and `advisor` cannot drift into searching different sets
    of catalogues for the same flags.
    """
    s = _settings()
    registry = build_source_registry(cache=cache)
    specs = registry.resolve(
        selection,
        all_sources=all_sources,
        include_optional=(
            s.include_hardened_sources if include_hardened is None else include_hardened
        ),
    )
    return await build_composite_repository(specs)


def available_source_names() -> list[str]:
    """`--source` choices, for help text and error messages."""
    return build_source_registry().names


async def build_recommend_use_case(
    max_critical: int | None = None,
    max_high: int | None = None,
    max_medium: int | None = None,
    workers: int | None = None,
    observer: ScanObserver | None = None,
    cross_validate: bool | None = None,
    verify_hub_tags: bool | None = None,
    include_hardened: bool | None = None,
    use_cache: bool = True,
    sources: Sequence[str] | None = None,
    all_sources: bool = False,
) -> RecommendImagesUseCase:
    s = _settings()
    # None means "not given on the command line", so the configured value
    # applies. Previously these carried hard-coded defaults that shadowed
    # Settings entirely, which made DOCKERLS_MAX_MEDIUM and the config file
    # silently do nothing.
    max_critical = validate_threshold(
        s.max_critical if max_critical is None else max_critical, "--max-critical"
    )
    max_high = validate_threshold(s.max_high if max_high is None else max_high, "--max-high")
    max_medium = validate_threshold(
        s.max_medium if max_medium is None else max_medium, "--max-medium"
    )
    workers = resolve_workers(workers)

    # `--no-cache` força uma medição nova: o cache é uma otimização, e às
    # vezes o que se quer é justamente contorná-lo.
    cache = build_cache() if use_cache else None
    repo = await build_sources(
        sources,
        all_sources=all_sources,
        include_hardened=include_hardened,
        cache=cache,
    )
    evidence = build_evidence_store()
    scanner = await ScannerFactory.create(
        timeout=s.scanner_timeout,
        workers=workers,
        cache_dir=s.trivy_cache_dir,
        evidence=evidence,
        guard=build_host_guard(),
    )
    eol = EndOfLifeChecker(
        timeout=s.http_timeout,
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )

    secondary = None
    if s.cross_validate if cross_validate is None else cross_validate:
        secondary = await ScannerFactory.create_secondary(
            scanner, timeout=s.scanner_timeout, evidence=evidence, guard=build_host_guard()
        )

    return RecommendImagesUseCase(
        repository=repo,
        hardening=build_hardening_analyzer(),
        resolve_digests=s.resolve_digests,
        scanner=scanner,
        eol_checker=eol,
        cache=cache,
        max_critical=max_critical,
        max_high=max_high,
        max_medium=max_medium,
        workers=workers,
        threat_intel=_threat_intel(),
        exploitdb=_exploitdb(),
        observer=observer,
        cross_validator=CrossValidator(
            secondary,
            # Capped at the primary worker count as well as the machine's:
            # cross-validation runs after the main pass, so it inherits the
            # same budget rather than opening a second, larger one.
            workers=min(resolve_workers(s.cross_validate_workers or None), workers),
        ),
        evidence=evidence,
        verify_hub_tags=s.verify_hub_tags if verify_hub_tags is None else verify_hub_tags,
        log_file=current_log_file(),
        cache_ttl_seconds=s.cache_ttl_seconds,
    )


def build_host_guard() -> HostGuard:
    """Where a reference is allowed to make this process connect.

    Built here rather than on `Settings` so the settings object stays a
    plain data holder and the policy is assembled in the one place that
    assembles everything else.
    """
    s = _settings()
    return HostGuard(
        NetworkPolicy(
            allow_private_networks=s.network_allow_private_networks,
            allow_loopback=s.network_allow_loopback,
            allow_link_local=s.network_allow_link_local,
            allowed_hosts=frozenset(s.network_allowed_hosts),
        )
    )


def build_hardening_analyzer() -> HardeningAnalyzer:
    """The registry-backed evidence gatherer, or a disabled one.

    With `inspect_image_config` off the analyzer still exists but has no
    inspector, so every hardening fact stays UNKNOWN and every dimension
    reports as not determined -- which is the honest result of choosing not
    to look, and is very different from reporting an image as clean.
    """
    s = _settings()
    inspector = (
        RegistryInspector(timeout=s.http_timeout, guard=build_host_guard())
        if s.inspect_image_config
        else None
    )
    return HardeningAnalyzer(inspector=inspector)


async def build_analyze_use_case() -> AnalyzeImageUseCase:
    s = _settings()
    repo = await build_repository()
    scanner = await ScannerFactory.create(timeout=s.scanner_timeout, guard=build_host_guard())
    eol = EndOfLifeChecker(
        timeout=s.http_timeout,
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )
    return AnalyzeImageUseCase(
        repository=repo,
        scanner=scanner,
        eol_checker=eol,
        threat_intel=_threat_intel(),
        exploitdb=_exploitdb(),
        hardening=build_hardening_analyzer(),
    )


async def build_compare_use_case() -> CompareImagesUseCase:
    analyze = await build_analyze_use_case()
    return CompareImagesUseCase(analyze_use_case=analyze)


async def build_search_use_case(
    sources: Sequence[str] | None = None,
    *,
    all_sources: bool = False,
) -> SearchImagesUseCase:
    """`search` goes through its use case like every other command, so the
    CLI never reaches past the application layer into a repository.

    With no selection this is Docker Hub alone, which is what `search` has
    always been: a listing of one repository's tags. `--source`/
    `--all-sources` widen it to the same catalogues `recommend` searches.
    """
    if sources is None and not all_sources:
        return SearchImagesUseCase(repository=await build_repository())
    return SearchImagesUseCase(repository=await build_sources(sources, all_sources=all_sources))
