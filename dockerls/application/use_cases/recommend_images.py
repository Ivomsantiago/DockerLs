from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import ValidationError

from dockerls import __version__
from dockerls.application.dto.analysis import (
    AnalysisResult,
    BaselineCriteria,
    ImageAnalysis,
    RunMetrics,
    UnverifiedImage,
)
from dockerls.application.services.progress import NullObserver
from dockerls.application.services.teardown import close_quietly, sources_of
from dockerls.application.services.verdict import (
    apply_facts,
    cross_validation_agreed,
    finalize_verdict,
    rank,
)
from dockerls.domain.entities.recommendation import (
    ActionType,
    Recommendation,
    RemediationStep,
)
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.scan_plan import DEFAULT_SCAN_BUDGET, plan_scans
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.integrations.registry.urls import source_url
from dockerls.utils.ignore_file import active_ignored_cve_ids, load_ignore_rules
from dockerls.utils.validation import validate_threshold, validate_workers

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from dockerls.application.services.cross_validation import CrossValidator
    from dockerls.application.services.hardening_analysis import HardeningAnalyzer
    from dockerls.application.services.progress import ScanObserver
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface
    from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.infrastructure.evidence import EvidenceStore
    from dockerls.integrations.exploitdb.client import ExploitDBClient, ExploitEntry
    from dockerls.integrations.threat_intel.client import ThreatIntelClient
    from dockerls.integrations.threat_intel.osv import OSVClient, OSVEnrichment

# How many ranked candidates are surfaced to the user.
TOP_N = 5


class UnverifiedRecommendationError(RuntimeError):
    """Raised when an image without a proven successful scan would have been
    presented as a recommendation. This is a programming error, not a user
    error: it means a code path bypassed the verification gate."""


class RecommendImagesUseCase:
    def __init__(
        self,
        repository: ImageRepositoryInterface,
        scanner: ScannerInterface,
        eol_checker: EOLCheckerInterface,
        cache: CacheStoreInterface | None = None,
        max_critical: int = 0,
        max_high: int = 0,
        max_medium: int = 5,
        workers: int = 10,
        ignore_path: Path | None = None,
        threat_intel: ThreatIntelClient | None = None,
        observer: ScanObserver | None = None,
        cross_validator: CrossValidator | None = None,
        evidence: EvidenceStore | None = None,
        verify_hub_tags: bool = True,
        log_file: Path | None = None,
        cache_ttl_seconds: int = 86400,
        hardening: HardeningAnalyzer | None = None,
        resolve_digests: bool = True,
        exploitdb: ExploitDBClient | None = None,
        osv: OSVClient | None = None,
        scan_budget: int = DEFAULT_SCAN_BUDGET,
    ):
        # Guarded at construction rather than only at the CLI boundary: the
        # use case is the last place that can refuse a value which would
        # otherwise deadlock the scan loop (`workers=0` blocks forever on a
        # semaphore) or silently invert the baseline (a negative threshold
        # can never be met). Any caller -- CLI, tests, a future API -- gets
        # the same refusal.
        self._repository = repository
        self._scanner = scanner
        self._eol_checker = eol_checker
        # Quantas tags este run pode medir. 0 mede todas, que é o
        # comportamento anterior e segue disponível por configuração.
        self._scan_budget = max(0, scan_budget)
        self._cache = cache
        self._max_critical = validate_threshold(max_critical, "max_critical")
        self._max_high = validate_threshold(max_high, "max_high")
        self._max_medium = validate_threshold(max_medium, "max_medium")
        self._workers = validate_workers(workers)
        self._ignored_cves = active_ignored_cve_ids(load_ignore_rules(ignore_path))
        self._threat_intel = threat_intel
        self._exploitdb = exploitdb
        self._osv = osv
        self._observer: ScanObserver = observer or NullObserver()
        self._cross_validator = cross_validator
        self._evidence = evidence
        self._verify_hub_tags = verify_hub_tags
        self._log_file = log_file
        self._cache_ttl_seconds = cache_ttl_seconds
        self._hardening = hardening
        self._resolve_digests = resolve_digests
        # Filled in once the scanner has been asked who it is. Until then the
        # fingerprint deliberately carries "unknown-scanner" rather than
        # nothing: a run that could not identify its scanner must not share
        # a cache namespace with one that could.
        self._scanner_identity = "unknown-scanner"
        self._analysis_fingerprint = self._compute_analysis_fingerprint()
        self._metrics = RunMetrics()

    def _compute_analysis_fingerprint(self) -> str:
        """Identifica as entradas, fora a própria imagem, que mudam o
        `ImageAnalysis` guardado em cache.

        As regras de ignore e o enriquecimento de threat intel são aplicados
        *antes* de cachear, mas a chave era só a referência da imagem. Um CVE
        que deixava de ser ignorado -- porque a regra foi removida, ou porque
        o `expires` dela venceu -- continuava suprimido até o TTL expirar
        (24h no padrão). O arquivo de ignore promete que uma isenção vencida
        deixa de valer; o cache desfazia essa promessa em silêncio.
        """
        material = "|".join(
            [
                ",".join(sorted(self._ignored_cves)),
                "threat-intel" if self._threat_intel is not None else "no-threat-intel",
                # Uma análise enriquecida com Exploit-DB carrega campos que a
                # anterior não tinha; servir a antiga esconderia a coluna.
                "exploitdb" if self._exploitdb is not None else "no-exploitdb",
                # Same reason: OSV enrichment adds osv_aliases/osv_affected_ranges.
                "osv" if self._osv is not None else "no-osv",
                # Which tool, at which version, produced the cached numbers.
                # Without this the cache served a Trivy result to a run using
                # Grype, and kept serving results from before a scanner
                # upgrade -- a stale measurement presented as a current one,
                # which is the same substitution this project refuses
                # everywhere else, just slower.
                self._scanner_identity,
                # And which version of *this* tool produced them. A cached
                # `ImageAnalysis` carries the score, the tier and the
                # readiness verdict, all of which are computed by policy
                # that lives here -- so a release that changes a penalty
                # weight, a tier threshold or a blocking rule would keep
                # serving verdicts decided under the previous rules until
                # the TTL ran out. `CACHE_SCHEMA_VERSION` does not cover
                # this: the payload's *shape* is unchanged, so validation
                # accepts it and only the meaning has moved.
                __version__,
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:12]

    async def _identify_scanner(self) -> None:
        """Ask the scanner who it is, and re-key the cache accordingly.

        Done once per run, before anything is read from or written to the
        cache. A scanner that cannot answer leaves the identity as
        "unknown-scanner", which is its own namespace: results whose
        provenance is unknown are reused only by other runs in the same
        situation.
        """
        version = getattr(self._scanner, "version", None)
        name = type(self._scanner).__name__
        if callable(version):
            try:
                reported = await version()
            except Exception as e:  # pragma: no cover - identity is best-effort
                logger.debug(f"Could not identify {name}: {e}")
                reported = ""
            if isinstance(reported, str) and reported:
                self._scanner_identity = reported
        self._metrics.scanner_identity = self._scanner_identity
        self._analysis_fingerprint = self._compute_analysis_fingerprint()
        logger.info(f"Scanner identity for this run: {self._scanner_identity}")

    def _cache_key(self, image: DockerImage) -> str:
        """Chaveia a análise pelo **digest** do manifesto, não pela tag.

        Tags são mutáveis: `node:22-alpine` de hoje não é a mesma imagem de
        ontem. Uma entrada chaveada por tag continuava servindo o resultado
        antigo por até 24h depois de um rebuild upstream -- ou seja, servia
        um veredito de segurança sobre uma imagem que não existe mais. O
        digest identifica bytes, então uma entrada só casa com a imagem que
        de fato produziu aquele scan.

        Sem digest (registries que listam só nomes de tag) a referência
        continua sendo a chave, que é o melhor disponível.
        """
        identity = image.digest or image.full_reference
        return f"analysis:{self._analysis_fingerprint}:{identity}"

    async def execute(self, image_name: str, limit: int = 100) -> AnalysisResult:
        try:
            return await self._execute(image_name, limit)
        finally:
            await self._close_scanners()
            await self._close_repositories()

    @staticmethod
    def _fallback_pool(analyses: list[ImageAnalysis]) -> list[ImageAnalysis]:
        """Ranking apresentado quando nada atinge o baseline.

        O filtro aqui era `critical_count == 0 and not is_eol` -- os mesmos
        critérios duros que o baseline já havia acabado de rejeitar. Quando
        toda tag candidata carregava um CRITICAL (o caso comum no Docker Hub),
        as "alternativas" saíam vazias também e o usuário recebia
        "No suitable images found" depois de esperar por uma centena de scans.
        Isso descarta a informação mais útil que a execução produziu: qual das
        imagens ruins é a menos ruim.

        Agora nada é descartado. As candidatas são apenas *ordenadas* pelo que
        importa nessa situação -- menos CRITICAL, menos HIGH, mais fácil de
        remediar, menos MEDIUM, maior score -- e a camada de apresentação diz
        com todas as letras que estão abaixo do alvo.
        """
        return sorted(
            analyses,
            key=lambda a: (
                a.is_eol,
                a.scan.critical_count,
                a.scan.high_count,
                -a.remediation_score,
                a.scan.medium_count,
                -a.security_score,
            ),
        )

    def _baseline(self) -> BaselineCriteria:
        return BaselineCriteria(
            max_critical=self._max_critical,
            max_high=self._max_high,
            max_medium=self._max_medium,
        )

    async def _execute(self, image_name: str, limit: int = 100) -> AnalysisResult:
        await self._identify_scanner()
        self._observer.phase("Preparing vulnerability database")
        setup_errors: list[str] = []
        refresh_db = getattr(self._scanner, "refresh_db", None)
        if callable(refresh_db) and not await refresh_db():
            # O retorno era descartado. Sem a DB pronta, cada worker sai
            # baixando a própria cópia em paralelo e o run inteiro reprova com
            # `init error: DB error` -- uma vez por tag. Registrar a causa raiz
            # uma única vez é o que transforma 93 linhas iguais num diagnóstico.
            logger.warning("Vulnerability database is not ready; scans are likely to fail")
            setup_errors.append(
                "Vulnerability database could not be prepared -- scan failures below are "
                "most likely a consequence of this, not of the images themselves"
            )

        self._observer.phase(f"Fetching tags for {image_name}")
        tags = await self._repository.search_tags(image_name, limit=limit)
        if not tags:
            return AnalysisResult(
                query=image_name,
                total_tags_scanned=0,
                baseline_met=False,
                errors=["No tags found for image"],
                log_file=str(self._log_file or ""),
                baseline=self._baseline(),
            )

        self._observer.phase_result(
            "Discovered tags",
            [
                ("found", str(len(tags))),
                ("sources", ", ".join(_sources_of(tags)) or "none"),
            ],
        )

        # Quem medir. Medir as 100 tags para mostrar cinco custa dois a
        # quatro minutos, e 95 desses scans existem só para serem
        # descartados no ranqueamento. O plano corta isso -- e declara o
        # que cortou: uma tag adiada não é uma tag pior, é uma tag *não
        # medida*, e ela aparece no resultado com o motivo.
        plan = plan_scans(tags, self._scan_budget)
        if plan.deferred:
            self._observer.phase_result(
                "Selected for measurement",
                [
                    ("measuring", str(len(plan.selected))),
                    ("deferred", str(plan.deferred_count)),
                    ("budget", str(plan.budget)),
                ],
            )
        tags = plan.selected

        await self._pin_digests(tags)

        analyses, unverified, errors = await self._scan_all(tags)
        errors = [*setup_errors, *errors]
        analyses.sort(key=lambda a: a.security_score, reverse=True)

        # Reported after the fact rather than before: the cache-hit and
        # scan counts are only known once the pass is done, and stating them
        # up front would mean guessing at them.
        self._observer.phase_result(
            "Scanned candidates",
            [
                ("unique digests", str(self._metrics.unique_digests)),
                ("duplicates collapsed", str(self._metrics.duplicates_collapsed)),
                ("cache hits", str(self._metrics.cache_hits)),
                ("scans performed", str(self._metrics.scans_performed)),
                ("digests pinned", str(self._metrics.digests_resolved)),
                ("unverified", str(len(unverified))),
            ],
        )

        baseline_images = [
            a
            for a in analyses
            if a.scan.critical_count <= self._max_critical
            and a.scan.high_count <= self._max_high
            and a.scan.medium_count <= self._max_medium
            and not a.is_eol
        ]

        if baseline_images:
            baseline_met = True
            pool = baseline_images
        else:
            baseline_met = False
            pool = self._fallback_pool(analyses)

        selected = await self._finalize(pool, unverified)

        result = AnalysisResult(
            query=image_name,
            total_tags_scanned=len(tags),
            total_tags_analyzed=len(analyses),
            baseline_met=baseline_met and bool(selected),
            recommendations=selected if baseline_met else [],
            alternatives=[] if baseline_met else selected,
            errors=errors,
            unverified=unverified,
            log_file=str(self._log_file or ""),
            baseline=self._baseline(),
            sources_searched=_sources_of(tags),
            metrics=self._metrics,
            deferred=plan.deferred,
            tags_discovered=plan.discovered,
        )
        result.evidence_manifest = await self._write_manifest(image_name, selected)
        return result

    async def _pin_digests(self, tags: list[DockerImage]) -> None:
        """Resolve every candidate that arrived without a digest.

        Deduplication keys on the digest, and a candidate with none is
        keyed by its reference instead -- so the same manifest published
        under `22`, `22-bookworm` and a hardened catalogue's alias is
        scanned three times. One HEAD per unresolved tag replaces those
        extra scans, and each scan costs orders of magnitude more than the
        request that avoids it.

        Failure is free: a registry that will not answer leaves the
        candidate exactly as it arrived.
        """
        if self._hardening is None or not self._resolve_digests:
            return
        unresolved = [tag for tag in tags if not tag.digest_known]
        if not unresolved:
            return

        self._observer.phase(f"Resolving digests for {len(unresolved)} tag(s)")
        semaphore = asyncio.Semaphore(self._workers)

        async def pin(image: DockerImage) -> None:
            async with semaphore:
                digest = await self._hardening.resolve_digest(image) if self._hardening else ""
            if digest:
                # Mutated in place because `tags` is the list the rest of
                # the pipeline holds; replacing entries would leave the
                # scan loop keyed on the unpinned copies.
                image.digest = digest
                self._metrics.digests_resolved += 1

        await asyncio.gather(*[pin(image) for image in unresolved])
        logger.info(
            f"Resolved {self._metrics.digests_resolved}/{len(unresolved)} previously "
            "unpinned tags to manifest digests"
        )

    async def _scan_all(
        self, tags: list[DockerImage]
    ) -> tuple[list[ImageAnalysis], list[UnverifiedImage], list[str]]:
        semaphore = asyncio.Semaphore(self._workers)
        errors: list[str] = []
        unverified: list[UnverifiedImage] = []

        # P0-3: dedupe scans by digest so tags sharing the same manifest
        # digest are only scanned once and share the result.
        scan_locks: dict[str, asyncio.Lock] = {}
        scan_cache: dict[str, Any] = {}

        def _dedup_key(image: DockerImage) -> str:
            return image.digest or image.full_reference

        self._metrics.tags_discovered = len(tags)
        self._metrics.unique_digests = len({_dedup_key(tag) for tag in tags})
        self._metrics.workers = self._workers

        # Caminho em lote: quando a engine Go está disponível, todos os
        # scans que faltam saem numa travessia de processo só, e
        # `scan_cache` chega aqui já preenchido. `get_scan` abaixo então
        # não dispara scan nenhum -- ele encontra tudo pela chave.
        #
        # `prefetched` são as análises que já estavam no cache do disco: o
        # lote tem de perguntar por elas *antes* de medir, ou um run
        # inteiramente cacheado voltaria a escanear cem imagens.
        prefetched, batched = await self._prescan(tags, scan_cache, _dedup_key)

        async def get_scan(image: DockerImage) -> Any:
            key = _dedup_key(image)
            lock = scan_locks.setdefault(key, asyncio.Lock())
            async with lock:
                if key in scan_cache:
                    return scan_cache[key]
                async with semaphore:
                    scan = await self._scanner.scan(image.full_reference)
                # Counted here rather than at the call site so a tag served
                # from a sibling's digest is never counted as a scan.
                self._metrics.scans_performed += 1
                scan_cache[key] = scan
                return scan

        def _skip(image: DockerImage, status: str, reason: str, kind: str = "UNKNOWN") -> None:
            logger.warning(f"Skipping {image.full_reference}: {status}/{kind} ({reason})")
            unverified.append(
                UnverifiedImage(
                    image_reference=image.full_reference,
                    status=status,
                    reason=reason or "no details",
                    kind=kind,
                )
            )
            errors.append(f"{image.full_reference}: {status}/{kind} ({reason or 'no details'})")

        async def analyze_tag(image: DockerImage) -> ImageAnalysis | None:
            self._observer.scanning(image.full_reference)
            analysis: ImageAnalysis | None = None
            try:
                # Já perguntado pelo lote; perguntar de novo seria uma
                # segunda leitura do cache por imagem.
                cached = (
                    prefetched.get(image.full_reference)
                    if batched
                    else await self._get_cached(image)
                )
                if cached:
                    self._metrics.cache_hits += 1
                    analysis = cached
                    return cached

                scan = await get_scan(image)
                # Single verification gate: anything short of a completed,
                # parsed scan is reported as unverified and is never scored.
                if not scan.is_verified:
                    _skip(image, scan.status.value, scan.error_message, scan.error_kind.value)
                    return None

                if self._ignored_cves:
                    scan = _apply_ignore_rules(scan, self._ignored_cves)
                if self._threat_intel is not None:
                    scan = await _enrich_with_threat_intel(
                        scan, self._threat_intel, self._exploitdb, self._osv
                    )

                product, version = _extract_product_version(image)
                eol_status = await _eol_status(self._eol_checker, product, version)
                is_eol = eol_status.is_true
                is_lts = await self._eol_checker.is_lts(product, version)

                score = SecurityScore(image, scan, is_eol=is_eol, is_lts=is_lts)
                tier = SecurityTier(scan, score.value, is_eol=is_eol)
                rem_score = RemediationScore(scan)

                analysis = ImageAnalysis(
                    image=image,
                    scan=scan,
                    security_score=score.value,
                    tier=tier.tier.value,
                    remediation_score=rem_score.value,
                    is_eol=is_eol,
                    eol_status=eol_status,
                    is_lts=is_lts,
                    evidence_paths=(
                        {scan.scanner: scan.evidence_path} if scan.evidence_path else {}
                    ),
                )

                await self._set_cached(image, analysis)
                return analysis
            except Exception as e:
                logger.warning(f"Failed to analyze {image.full_reference}: {e}")
                _skip(image, "ERROR", str(e))
                return None
            finally:
                self._observer.finished(image.full_reference, analysis is not None)

        self._observer.start(len(tags))
        results = await asyncio.gather(*[analyze_tag(tag) for tag in tags])
        return [r for r in results if r is not None], unverified, errors

    async def _prescan(
        self,
        tags: list[DockerImage],
        scan_cache: dict[str, Any],
        dedup_key: Callable[[DockerImage], str],
    ) -> tuple[dict[str, ImageAnalysis], bool]:
        """Mede o lote inteiro de uma vez, quando a engine Go existe.

        O que muda em relação ao caminho de sempre não é o scan: o Trivy
        continua sendo o Trivy e continua custando o que custa. O que muda
        é o entorno -- criar e colher N processos, revezar o diretório de
        cache, coordenar o dedup por digest -- que sai de N travessias
        Python<->processo para uma.

        Devolve `(análises já em cache, se o lote aconteceu)`. Quando o
        lote não acontece -- engine ausente, versão incompatível, qualquer
        falha -- devolve `({}, False)` e o pipeline segue exatamente como
        antes. A engine é uma otimização, e uma otimização que pode
        derrubar o comando não vale o ganho.
        """
        batch = getattr(self._scanner, "batch", None)
        if batch is None:
            return {}, False

        # O cache do disco vem primeiro: um run inteiramente cacheado tem
        # de continuar fazendo zero scans, e medir para depois descobrir
        # que a resposta já estava guardada seria o pior dos dois mundos.
        cached_analyses = await asyncio.gather(*[self._get_cached(tag) for tag in tags])
        prefetched = {
            tag.full_reference: analysis
            for tag, analysis in zip(tags, cached_analyses, strict=True)
            if analysis is not None
        }

        pending: list[tuple[str, str]] = []
        seen: set[str] = set()
        for tag in tags:
            if tag.full_reference in prefetched:
                continue
            key = dedup_key(tag)
            if key in seen:
                continue
            seen.add(key)
            pending.append((tag.full_reference, key))

        if not pending:
            return prefetched, True

        outcome = await batch.scan_batch(pending)
        if outcome is None:
            # A engine recusou o lote. As análises já lidas do cache não se
            # perdem, mas o caminho individual precisa reler -- devolver
            # `batched=True` aqui faria toda imagem não cacheada ser
            # tratada como sem cache *e* sem scan.
            return {}, False

        for (_, key), result in zip(pending, outcome.results, strict=True):
            scan_cache[key] = result
        self._metrics.scans_performed += outcome.scans_performed
        logger.info(
            f"Go engine measured {len(pending)} targets in {outcome.wall_seconds:.1f}s "
            f"({outcome.scans_performed} scans, {outcome.duplicates_collapsed} collapsed)"
        )
        return prefetched, True

    async def _finalize(
        self, pool: list[ImageAnalysis], unverified: list[UnverifiedImage]
    ) -> list[ImageAnalysis]:
        """Cross-validate, confirm Docker Hub tags, and enforce the
        no-scan-no-recommendation invariant on the final candidate list."""
        # Verify a wider slice than TOP_N so candidates dropped for a
        # missing Hub tag can be backfilled from the next best ones.
        candidates = pool[: TOP_N * 2]

        # A verificação de tag vem primeiro, e a cross-validation só depois,
        # sobre quem sobreviveu. Na ordem inversa, um candidato promovido
        # para o top N no lugar de um descartado entrava na tabela sem nunca
        # ter passado pelo segundo scanner -- ou seja, com a pontuação
        # apresentada sem contestação justamente por não ter sido checada.
        # De quebra, deixa de gastar um scan secundário em quem vai cair.
        if self._verify_hub_tags and candidates:
            self._observer.phase("Verifying tags in their source registries")
            await self._verify_tags(candidates, unverified)
            candidates = [c for c in candidates if c.hub_tag_verified is not False]

        selected = candidates[:TOP_N]

        if self._cross_validator is not None and self._cross_validator.enabled and selected:
            self._observer.phase(f"Cross-validating top {len(selected)} candidates")
            self._metrics.cross_validations = len(selected)
            await self._cross_validator.validate(selected)

        # Hardening evidence is gathered for the finalists only. Inspecting
        # every discovered tag would cost two registry round-trips each --
        # hundreds of requests to inform a decision between five images --
        # and the candidates that reach this point are exactly the ones the
        # decision is actually between.
        await self._inspect(selected)

        for analysis in selected:
            finalize_verdict(analysis, cross_validated=cross_validation_agreed(analysis))

        # The final ordering is the multi-source one: confidence first, then
        # the measured vulnerability position, then hardening and surface.
        # Up to here the pool was ordered by security score alone, which
        # could not see the evidence that has just been gathered.
        selected = rank(selected)

        _assert_verified(selected)
        for analysis in selected:
            analysis.recommendation = build_recommendation(analysis)
        return selected

    async def _inspect(self, selected: list[ImageAnalysis]) -> None:
        """Attach registry/catalogue/scanner evidence to each finalist."""
        if self._hardening is None or not selected:
            return
        self._observer.phase(f"Inspecting {len(selected)} candidate image(s)")

        async def inspect(analysis: ImageAnalysis) -> None:
            if self._hardening is None:
                return
            digest, facts = await self._hardening.analyze(analysis.image, analysis.scan)
            if digest and not analysis.image.digest_known:
                analysis.image.digest = digest
            apply_facts(analysis, facts)
            if facts.config_verified:
                self._metrics.images_inspected += 1

        await asyncio.gather(*[inspect(a) for a in selected])

    async def _verify_tags(
        self, candidates: list[ImageAnalysis], unverified: list[UnverifiedImage]
    ) -> None:
        """Confirm each candidate tag against the registry that owns it.

        Docker Hub tags are checked through the Hub API; hardened-source
        tags are checked against that source's own listing. Either way the
        answer comes from the registry, never from a constructed string.
        """
        checker = getattr(self._repository, "tag_exists", None)

        async def check(analysis: ImageAnalysis) -> None:
            analysis.hub_url = source_url(analysis.image.name, analysis.image.tag)
            if not callable(checker):
                return
            exists = await checker(analysis.image.name, analysis.image.tag)
            analysis.hub_tag_verified = exists
            if exists is False:
                logger.warning(
                    f"Dropping {analysis.image.full_reference}: "
                    f"tag not found in {analysis.image.source}"
                )
                unverified.append(
                    UnverifiedImage(
                        image_reference=analysis.image.full_reference,
                        status="TAG_NOT_FOUND",
                        reason=f"Tag does not exist in {analysis.image.source}",
                    )
                )

        await asyncio.gather(*[check(c) for c in candidates])

    async def _write_manifest(self, query: str, selected: list[ImageAnalysis]) -> str:
        if self._evidence is None or not selected:
            return ""
        entries = [
            {
                "image": a.image.full_reference,
                "pinned_reference": a.image.pinned_reference,
                "digest": a.image.digest,
                "confidence": a.confidence.value,
                "production_ready": a.production_ready,
                "readiness_blockers": a.readiness_blockers,
                "cross_validation": a.cross_validation,
                "security_score": a.security_score,
                "tier": a.tier,
                "critical": a.scan.critical_count,
                "high": a.scan.high_count,
                "medium": a.scan.medium_count,
                "scan_status": a.scan.status.value,
                "scan_timestamp": a.scan.scan_timestamp,
                "scan_divergence": a.scan_divergence,
                "hub_url": a.hub_url,
                "hub_tag_verified": a.hub_tag_verified,
                "evidence": a.evidence_paths,
            }
            for a in selected
        ]
        return await self._evidence.record_manifest(
            query,
            entries,
            provenance={
                "dockerls_version": __version__,
                "scanner": self._scanner_identity,
                "resolved_at": datetime.now(tz=UTC).isoformat(),
                "analysis_fingerprint": self._analysis_fingerprint,
            },
        )

    async def _close_scanners(self) -> None:
        secondary = self._cross_validator.scanner if self._cross_validator else None
        await close_quietly(self._scanner, secondary, self._hardening)

    async def _close_repositories(self) -> None:
        """Release the HTTP connection pools the image sources hold.

        The clients keep one `httpx.AsyncClient` alive for the whole run so
        connections are reused; that makes closing them the caller's job.
        """
        await close_quietly(*sources_of(self._repository))

    async def _get_cached(self, image: DockerImage) -> ImageAnalysis | None:
        key = image.full_reference
        if not self._cache:
            return None
        cache_key = self._cache_key(image)
        try:
            data = await self._cache.get(cache_key)
        except Exception as e:
            # An unreadable cache is a miss, not a scan failure.
            logger.warning(f"Could not read cached analysis for {key}: {e}")
            return None
        if not (data and isinstance(data, dict)):
            return None
        try:
            analysis: ImageAnalysis = ImageAnalysis.model_validate(data)
        except ValidationError as e:
            logger.warning(f"Discarding stale cache entry for {key}: {e}")
            await self._discard(cache_key)
            return None
        # A cache hit is not proof of a successful scan: an entry written by
        # an older build could carry a failed scan. Re-apply the gate.
        if not analysis.scan.is_verified:
            logger.warning(f"Discarding cache entry for {key}: cached scan is not verified")
            await self._discard(cache_key)
            return None
        return analysis

    async def _discard(self, cache_key: str) -> None:
        """Best-effort eviction: failing to delete a bad entry must not
        become a failure to analyze the image it belongs to."""
        if not self._cache:
            return
        try:
            await self._cache.delete(cache_key)
        except Exception as e:
            logger.warning(f"Could not evict cache entry {cache_key}: {e}")

    async def _set_cached(self, image: DockerImage, analysis: ImageAnalysis) -> None:
        key = image.full_reference
        """Persist an analysis, treating a storage failure as a cache miss.

        The cache is an optimisation, never a source of truth. Letting a
        write error escape put it on the same path as a failed scan: the
        exception unwound into `analyze_tag`'s handler, which reported a
        fully-scanned, fully-scored image as `ERROR`/unverified. A locked
        SQLite file -- ordinary under the concurrency this use case creates
        -- was enough to make a clean image vanish from the results.
        """
        if not self._cache:
            return
        try:
            await self._cache.set(
                self._cache_key(image),
                analysis.model_dump(),
                ttl_seconds=self._cache_ttl_seconds,
            )
        except Exception as e:
            logger.warning(f"Could not cache analysis for {key}: {e}")


def _sources_of(tags: list[DockerImage]) -> list[str]:
    """Distinct catalogues that contributed a candidate, in first-seen
    order, so the run can report what it actually looked at."""
    seen: list[str] = []
    for tag in tags:
        if tag.source not in seen:
            seen.append(tag.source)
    return seen


def _assert_verified(analyses: list[ImageAnalysis]) -> None:
    """Final gate before results leave the use case.

    Nothing reaches the user's "Recommended Images" table without a scan
    result that exists, completed successfully, and produced a timestamp.
    """
    offenders = [
        a.image.full_reference for a in analyses if a.scan is None or not a.scan.is_verified
    ]
    if offenders:
        raise UnverifiedRecommendationError(
            f"Refusing to recommend images without a verified scan: {', '.join(offenders)}"
        )


async def _exploitdb_lookup(
    exploitdb: ExploitDBClient | None, cve_ids: list[str]
) -> dict[str, list[ExploitEntry]]:
    """Consulta o Exploit-DB sem deixar a falha dela derrubar o resto.

    O cliente já degrada sozinho, mas este comando enriquece dezenas de tags
    em paralelo e uma exceção inesperada aqui abortaria a análise inteira de
    uma imagem por causa de uma fonte que é, por definição, opcional.
    """
    if exploitdb is None:
        return {}
    try:
        return await exploitdb.exploits_for(cve_ids)
    except Exception as e:  # pragma: no cover - o cliente já trata o previsível
        logger.warning(f"Exploit-DB lookup failed, exploit status stays UNKNOWN: {e}")
        return {}


def _exploitdb_fields(entries: list[ExploitEntry] | None, *, available: bool) -> dict[str, Any]:
    """Os três campos de explorabilidade, ou nada quando nada foi consultado.

    Com a fonte indisponível os campos não são tocados: o default do modelo
    é UNKNOWN, e escrever FALSE aqui transformaria uma consulta que não
    aconteceu numa afirmação de que não existe exploit publicado.
    """
    if not available:
        return {}
    if not entries:
        return {"exploitdb_status": Tristate.FALSE}
    return {
        "exploitdb_status": Tristate.TRUE,
        "exploitdb_ids": [e.edb_id for e in entries],
        # Um único exploit verificado já basta: a pergunta é se existe prova
        # reproduzida, não se todas as entradas foram reproduzidas.
        "exploitdb_verified": any(e.verified for e in entries),
    }


async def _osv_lookup(osv: OSVClient | None, cve_ids: list[str]) -> dict[str, OSVEnrichment]:
    """Same shape as `_exploitdb_lookup`: an unexpected exception here must
    degrade this optional source, not the whole enrichment pass."""
    if osv is None:
        return {}
    try:
        return await osv.enrich(cve_ids)
    except Exception as e:  # pragma: no cover - o cliente já trata o previsível
        logger.warning(f"OSV.dev lookup failed, no supplementary data attached: {e}")
        return {}


async def _enrich_with_threat_intel(
    scan: Any,
    threat_intel: ThreatIntelClient,
    exploitdb: ExploitDBClient | None = None,
    osv: OSVClient | None = None,
) -> Any:
    """Tag CRITICAL/HIGH vulnerabilities with CISA KEV / EPSS / Exploit-DB signal.

    The enrichment records *whether the feeds answered*, not just what they
    said. With the KEV catalogue unreachable every lookup returns the empty
    set, and marking each CVE `exploit_known=False` on that basis turned a
    failed request into an affirmative safety claim -- the report went on to
    state that the image had no known-exploited vulnerabilities. So a
    CVE now carries `kev_status`: TRUE (listed), FALSE (catalogue answered
    and does not list it), UNKNOWN (nothing was consulted).

    Exploit-DB rides the same entry point rather than a second pass: it is
    the same question about the same CVEs, and a separate flow would mean
    two places to keep the "absent lookup is never a negative" rule in.
    KEV and Exploit-DB are not redundant -- KEV means observed exploitation
    in the wild, Exploit-DB means published exploit code -- so a CVE can
    carry one and not the other.

    OSV.dev rides the same entry point too, but it answers a different kind
    of question: it never sets a verdict field, only `osv_aliases` and
    `osv_affected_ranges` -- supplementary identifiers and ranges that
    complement what Trivy/Grype already reported, never overwrite it. An
    absent OSV answer for a CVE simply leaves those two fields empty; there
    is no false-negative to guard against because nothing here asserts
    "not exploitable" on OSV's behalf.

    Enrichment is attempted only for CRITICAL/HIGH findings, so anything
    below stays UNKNOWN by construction -- which is correct: it was not
    looked up.
    """
    notable_ids = [
        v.cve_id
        for v in scan.vulnerabilities
        if v.severity.value in ("CRITICAL", "HIGH") and v.cve_id
    ]
    if not notable_ids:
        return scan

    # As quatro fontes respondem sobre o mesmo lote de CVEs e não dependem
    # uma da outra -- pedi-las em sequência somava a latência de todas num
    # scan que já espera pelo scanner. Uma falha isolada não derruba as
    # outras: cada chamada já degrada sozinha para o tri-state UNKNOWN (ou,
    # no caso do OSV, para campos de enriquecimento simplesmente vazios).
    kev_ids, epss, exploits, osv_data = await asyncio.gather(
        threat_intel.known_exploited(notable_ids),
        threat_intel.epss_scores(notable_ids),
        _exploitdb_lookup(exploitdb, notable_ids),
        _osv_lookup(osv, notable_ids),
    )
    exploitdb_available = exploitdb is not None and bool(exploitdb.available)
    kev_available = _answered(threat_intel.kev_available, bool(kev_ids))
    epss_available = _answered(threat_intel.epss_available, bool(epss))
    if not kev_available and not epss_available and not exploitdb_available and not osv_data:
        # Nothing was learned. Returning the scan untouched leaves every
        # `kev_status` at UNKNOWN, which is exactly what happened.
        logger.warning(
            "Threat intelligence unavailable: exploitation status stays UNKNOWN for "
            f"{len(notable_ids)} finding(s) in {scan.image_reference}"
        )
        return scan

    timestamp = datetime.now(tz=UTC).isoformat()
    notable = set(notable_ids)
    updated = []
    for v in scan.vulnerabilities:
        if v.cve_id not in notable:
            updated.append(v)
            continue
        key = v.cve_id.upper()
        listed = key in kev_ids
        score = epss.get(key)
        osv_enrichment = osv_data.get(key)
        updated.append(
            v.model_copy(
                update={
                    "exploit_known": listed,
                    "kev_status": Tristate.of(listed) if kev_available else Tristate.UNKNOWN,
                    "epss_score": score if score is not None else v.epss_score,
                    "epss_known": epss_available and score is not None,
                    "epss_percentile": threat_intel.percentile_of(key),
                    "threat_intel_timestamp": timestamp,
                    **_exploitdb_fields(exploits.get(key), available=exploitdb_available),
                    **(
                        {
                            "osv_aliases": osv_enrichment.aliases,
                            "osv_affected_ranges": osv_enrichment.affected_ranges,
                        }
                        if osv_enrichment is not None
                        else {}
                    ),
                }
            )
        )
    return scan.model_copy(update={"vulnerabilities": updated})


async def _eol_status(checker: Any, product: str, version: str) -> Tristate:
    """The three-valued lifecycle answer, from a checker that can give one.

    Dispatched dynamically for the same reason `tag_exists` and `refresh_db`
    are: `EOLCheckerInterface` predates the tri-state, and every test double
    and alternative implementation in the wild implements the boolean. A
    checker that only answers `is_eol` can distinguish TRUE from
    "not TRUE", and "not TRUE" is honestly reported as FALSE only because
    that is the entire content of what it said -- the richer checker is the
    one that gets to say UNKNOWN.
    """
    status = getattr(checker, "eol_status", None)
    if callable(status):
        result = await status(product, version)
        # The answer is validated, not assumed: `getattr` on a test double
        # (or on any object with dynamic attributes) happily produces a
        # callable that returns something else entirely, and a value that is
        # not a Tristate must not be coerced into one -- `bool(mock)` is
        # True, which would silently declare every image end-of-life.
        if isinstance(result, Tristate):
            return result
        logger.debug(
            f"{type(checker).__name__}.eol_status returned {type(result).__name__}, "
            "not a Tristate; falling back to is_eol"
        )
    return Tristate.of(await checker.is_eol(product, version))


def _answered(reported: bool | None, produced_data: bool) -> bool:
    """Whether a threat-intel source actually answered.

    The client records this directly, and that record is authoritative in
    both directions. `None` means nothing set it -- a source that was never
    queried, or a substitute that does not track it -- and there the only
    evidence available is the payload itself: data that came back proves the
    source answered, while an empty result proves nothing either way and is
    treated as "not consulted".

    The asymmetry is the whole point. Erring towards UNKNOWN costs a
    confidence level; erring towards "answered" would let a dead feed
    produce the sentence "no known-exploited vulnerabilities".
    """
    if reported is not None:
        return reported
    return produced_data


def _apply_ignore_rules(scan: Any, ignored_cves: set[str]) -> Any:
    """Return a copy of `scan` with vulnerabilities matching an active
    .dockerls-ignore.yaml rule removed, so ignored CVEs never affect
    scoring, tiering, or the baseline decision."""
    filtered = [v for v in scan.vulnerabilities if v.cve_id.upper() not in ignored_cves]
    if len(filtered) == len(scan.vulnerabilities):
        return scan
    return scan.model_copy(update={"vulnerabilities": filtered})


_LEADING_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}")


def _extract_product_version(image: DockerImage) -> tuple[str, str]:
    name = image.name.split("/")[-1]
    match = _LEADING_VERSION_RE.match(image.tag)
    version = match.group(0) if match else ""
    return name, version


def build_recommendation(analysis: ImageAnalysis) -> Recommendation:
    steps: list[RemediationStep] = []
    step_num = 1

    if analysis.scan.fixable_high_count > 0 or analysis.scan.fixable_critical_count > 0:
        fixable_pkgs = [
            v
            for v in analysis.scan.vulnerabilities
            if v.is_fixable and v.severity.value in ("CRITICAL", "HIGH")
        ]
        for vuln in fixable_pkgs[:5]:
            steps.append(
                RemediationStep(
                    step_number=step_num,
                    action=ActionType.UPDATE_PACKAGE,
                    description=f"Update {vuln.package_name}",
                    from_value=vuln.installed_version,
                    to_value=vuln.fixed_version,
                    expected_impact=f"Fix {vuln.severity.value} {vuln.cve_id}",
                )
            )
            step_num += 1

    if not analysis.image.is_alpine and not analysis.image.is_distroless:
        steps.append(
            RemediationStep(
                step_number=step_num,
                action=ActionType.SWITCH_BASE,
                description="Consider switching to Alpine or Distroless variant",
                expected_impact="Reduced attack surface",
            )
        )
        step_num += 1

    steps.append(
        RemediationStep(
            step_number=step_num,
            action=ActionType.REBUILD_IMAGE,
            description="Rebuild image to pick up latest base layer patches",
        )
    )
    step_num += 1

    steps.append(
        RemediationStep(
            step_number=step_num,
            action=ActionType.RESCAN,
            description="Re-run vulnerability scan to verify fixes",
        )
    )

    summary_parts = []
    if analysis.scan.critical_count == 0 and analysis.scan.high_count == 0:
        summary_parts.append("Image meets security baseline.")
    elif analysis.scan.critical_count == 0:
        summary_parts.append(
            f"Image has {analysis.scan.high_count} HIGH vulnerabilities "
            f"({analysis.scan.fixable_high_count} fixable)."
        )
    else:
        summary_parts.append(
            f"Image has {analysis.scan.critical_count} CRITICAL and "
            f"{analysis.scan.high_count} HIGH vulnerabilities."
        )
    if analysis.remediation_score == 100:
        summary_parts.append("All vulnerabilities have available fixes.")
    if analysis.scan_divergence:
        summary_parts.append(f"Scanner disagreement: {analysis.scan_divergence}.")

    return Recommendation(
        image_reference=analysis.image.full_reference,
        security_score=analysis.security_score,
        tier=analysis.tier,
        remediation_score=analysis.remediation_score,
        steps=steps,
        summary=" ".join(summary_parts),
    )
