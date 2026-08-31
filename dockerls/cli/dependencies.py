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
from dockerls.cli.runtime import (
    _settings,
    configure_logging,
    current_log_file,
    enable_console_logging,
)
from dockerls.domain.entities.image import DOCKER_HUB
from dockerls.domain.value_objects.network_policy import NetworkPolicy
from dockerls.infrastructure.evidence import EvidenceStore
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
from dockerls.integrations.registry.private import PRIVATE_REGISTRY, PrivateRegistryRepository
from dockerls.integrations.threat_intel.client import ThreatIntelClient
from dockerls.integrations.threat_intel.osv import OSVClient
from dockerls.utils.auth import load_credentials
from dockerls.utils.resources import describe_capacity, recommended_workers
from dockerls.utils.validation import validate_threshold, validate_workers

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from dockerls.application.services.progress import ScanObserver
    from dockerls.application.services.source_registry import SourceBuilder
    from dockerls.cache.sqlite_cache import SQLiteCache
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface

# As Settings e o logging moram em `cli/runtime.py`, que não arrasta este
# módulo junto: o callback de bootstrap precisa deles antes de todo
# subcomando, e importar o contêiner inteiro para configurar um sink era o
# que fazia `dockerls version` custar o mesmo que `dockerls advisor`.
# Reexportados aqui porque todo chamador -- e todo teste -- já os importa
# deste módulo.
__all__ = [
    "_settings",
    "configure_logging",
    "current_log_file",
    "enable_console_logging",
]


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
        guard=build_host_guard(),
    )
    if username and token:
        await client.authenticate()
    return client


@lru_cache(maxsize=1)
def build_cache() -> SQLiteCache:
    # Import tardio: `SQLiteCache` puxa o SQLAlchemy, que sozinho responde por
    # cerca de um segundo do arranque do processo. Comandos que nunca tocam o
    # cache -- `version`, `--help`, `controls`, `policy` -- pagavam esse
    # segundo em toda invocação, e um segundo de espera antes de um `--help` é
    # o tipo de coisa que faz uma ferramenta parecer pesada sem ser.
    from dockerls.cache.sqlite_cache import SQLiteCache

    s = _settings()
    return SQLiteCache(s.db_path)


def close_cache() -> None:
    """Dispose the shared SQLite engine, if a command ever built one.

    Called once, after the command finishes (see `cli/app.py`). Every
    caller of `build_cache()` -- `recommend`, `cache`, `registry-audit`,
    `_threat_intel`, `_exploitdb` -- gets the same memoized instance, so
    there is exactly one engine to close per process, and a command that
    never touched the cache (`version`, `--help`) never built one: this is
    then a no-op that costs nothing.
    """
    if build_cache.cache_info().currsize:
        build_cache().close()
        build_cache.cache_clear()


@lru_cache(maxsize=1)
def _threat_intel() -> ThreatIntelClient | None:
    """KEV catalogue and EPSS scores, cached to disk like Exploit-DB below.

    Both feeds move roughly once a day, so without a disk cache every single
    invocation re-downloaded the whole KEV catalogue and re-queried FIRST.org
    for every CRITICAL/HIGH CVE from scratch -- including two `recommend`
    runs back to back against the same image a minute apart.
    """
    s = _settings()
    if not s.enable_threat_intel:
        return None
    return ThreatIntelClient(
        timeout=s.http_timeout,
        cache=build_cache(),
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )


@lru_cache(maxsize=1)
def _exploitdb() -> ExploitDBClient | None:
    """O catálogo do Exploit-DB, atrás da mesma chave que KEV/EPSS.

    Segue `enable_threat_intel` porque responde à mesma pergunta -- quão
    explorável é isto -- e quem desliga o enriquecimento não quer que este
    fique de fora. Recebe o cache em disco pelo mesmo motivo do
    `ThreatIntelClient`: o CSV tem cerca de 10 MB, e rebaixá-lo a cada
    invocação seria pagar o download inteiro para reler o mesmo dia de
    catálogo.
    """
    s = _settings()
    if not s.enable_threat_intel:
        return None
    return ExploitDBClient(
        timeout=s.http_timeout,
        cache=build_cache(),
        guard=build_host_guard(),
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )


@lru_cache(maxsize=1)
def _osv() -> OSVClient | None:
    """OSV.dev advisory enrichment (aliases, affected ranges), atrás da
    mesma chave que KEV/EPSS/Exploit-DB -- é a mesma decisão de "quanto
    threat intel esta execução envia para fora", e quem a desliga não quer
    que esta fonte fique de fora dela.
    """
    s = _settings()
    if not s.enable_threat_intel:
        return None
    return OSVClient(
        timeout=s.http_timeout,
        cache=build_cache(),
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )


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
            build=_source_builder(
                lambda: ChainguardRepository(
                    timeout=s.http_timeout,
                    guard=build_host_guard(),
                    max_attempts=s.retry_max_attempts,
                    backoff_base=s.retry_backoff_base,
                )
            ),
            default_enabled=s.include_hardened_sources,
            description="Chainguard free tier (cgr.dev)",
        )
    )
    registry.register(
        SourceSpec(
            name="distroless",
            label=DISTROLESS,
            build=_source_builder(
                lambda: DistrolessRepository(
                    timeout=s.http_timeout,
                    guard=build_host_guard(),
                    max_attempts=s.retry_max_attempts,
                    backoff_base=s.retry_backoff_base,
                )
            ),
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
    if s.private_registry_host:
        # Registered only when a host is actually configured: an option
        # with nothing behind it would make `--source private` fail with
        # "no repository named that" instead of the CLI's own unknown-
        # source message, and would list a source in `--help`/`doctor`
        # that cannot do anything.
        registry.register(
            SourceSpec(
                name="private",
                label=PRIVATE_REGISTRY,
                build=_source_builder(
                    lambda: PrivateRegistryRepository(
                        s.private_registry_host,
                        s.private_registry_namespace,
                        timeout=s.http_timeout,
                        guard=build_host_guard(),
                        username=s.private_registry_username,
                        password=s.private_registry_password,
                        max_attempts=s.retry_max_attempts,
                        backoff_base=s.retry_backoff_base,
                    )
                ),
                default_enabled=False,
                requires_auth=bool(s.private_registry_username),
                description=f"Private registry ({s.private_registry_host})",
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
    scan_budget: int | None = None,
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
            scanner,
            timeout=s.scanner_timeout,
            evidence=evidence,
            guard=build_host_guard(),
            # O mesmo teto do passo principal: a cross-validação roda depois
            # dele e herda o orçamento, em vez de abrir um segundo maior.
            workers=min(resolve_workers(s.cross_validate_workers or None), workers),
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
        osv=_osv(),
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
        scan_budget=s.scan_budget if scan_budget is None else scan_budget,
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


def build_registry_credentials() -> dict[str, tuple[str, str]]:
    """Host -> (username, password) for every registry this run has
    credentials for -- the configured private registry, today.

    `RegistryInspector` resolves a reference by its host, not by a
    `--source` name, so `analyze`/`compare`/`alternatives` -- which take a
    reference directly, never a source -- reach the same credentials
    `--source private` uses for `recommend`/`search` through this instead
    of a second, separate configuration.
    """
    s = _settings()
    if not (s.private_registry_host and s.private_registry_username):
        return {}
    return {s.private_registry_host: (s.private_registry_username, s.private_registry_password)}


def build_hardening_analyzer() -> HardeningAnalyzer:
    """The registry-backed evidence gatherer, or a disabled one.

    With `inspect_image_config` off the analyzer still exists but has no
    inspector, so every hardening fact stays UNKNOWN and every dimension
    reports as not determined -- which is the honest result of choosing not
    to look, and is very different from reporting an image as clean.
    """
    s = _settings()
    inspector = (
        RegistryInspector(
            timeout=s.http_timeout,
            guard=build_host_guard(),
            credentials=build_registry_credentials(),
            max_attempts=s.retry_max_attempts,
            backoff_base=s.retry_backoff_base,
        )
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
    # Import tardio, como o resto do módulo: essas duas stores só custam algo
    # quando algum comando de fato as usa.
    from dockerls.application.services.scan_history_store import ScanHistoryStore
    from dockerls.application.services.tag_history_store import TagHistoryStore

    cache = build_cache()
    return AnalyzeImageUseCase(
        repository=repo,
        scanner=scanner,
        eol_checker=eol,
        threat_intel=_threat_intel(),
        exploitdb=_exploitdb(),
        osv=_osv(),
        hardening=build_hardening_analyzer(),
        tag_history=TagHistoryStore(cache),
        scan_history=ScanHistoryStore(cache),
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
