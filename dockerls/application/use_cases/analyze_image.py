from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.teardown import close_quietly, sources_of
from dockerls.application.services.verdict import apply_facts, finalize_verdict
from dockerls.application.use_cases.recommend_images import (
    _enrich_with_threat_intel,
    _eol_status,
)
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.image_reference import split_repository_and_tag
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier
from dockerls.utils.ignore_file import active_ignored_cve_ids, load_ignore_rules

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.services.hardening_analysis import HardeningAnalyzer
    from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.integrations.exploitdb.client import ExploitDBClient
    from dockerls.integrations.threat_intel.client import ThreatIntelClient


class AnalyzeImageUseCase:
    def __init__(
        self,
        repository: ImageRepositoryInterface,
        scanner: ScannerInterface,
        eol_checker: EOLCheckerInterface,
        ignore_path: Path | None = None,
        threat_intel: ThreatIntelClient | None = None,
        hardening: HardeningAnalyzer | None = None,
        exploitdb: ExploitDBClient | None = None,
    ):
        self._repository = repository
        self._scanner = scanner
        self._eol_checker = eol_checker
        self._ignored_cves = active_ignored_cve_ids(load_ignore_rules(ignore_path))
        self._threat_intel = threat_intel
        self._hardening = hardening
        self._exploitdb = exploitdb

    async def execute(self, image_reference: str) -> ImageAnalysis:
        name, tag = self._parse_reference(image_reference)
        image = await self._repository.get_image_metadata(name, tag)
        if not image:
            image = DockerImage(name=name, tag=tag)
            if "@" in image_reference:
                # Um digest é a identidade exata de um conjunto de bytes, e
                # `name:tag` não o reproduz: reconstruir mandaria o scanner
                # medir `node:latest` no lugar do digest que foi pedido --
                # outra imagem, apresentada com o nome desta.
                image.full_reference = image_reference

        scan = await self._scanner.scan(image.full_reference)
        if self._ignored_cves:
            filtered = [
                v for v in scan.vulnerabilities if v.cve_id.upper() not in self._ignored_cves
            ]
            if len(filtered) != len(scan.vulnerabilities):
                scan = scan.model_copy(update={"vulnerabilities": filtered})
        if self._threat_intel is not None:
            scan = await _enrich_with_threat_intel(scan, self._threat_intel, self._exploitdb)

        product = name.split("/")[-1]
        match = re.match(r"^\d+(?:\.\d+){0,3}", tag)
        version = match.group(0) if match else ""

        eol_status = await _eol_status(self._eol_checker, product, version)
        is_eol = eol_status.is_true
        is_lts = await self._eol_checker.is_lts(product, version)

        # `SecurityScore` requires a completed scan and raises on anything
        # else. A failed scan is not scored at all here: the tier falls back
        # to F (0.0), and `finalize_verdict` below reads `scan.is_verified`
        # to keep that from ever being reported as a verdict rather than a
        # measurement failure -- the same gate `recommend` applies before it
        # will construct a `SecurityScore` in the first place.
        security_score = 0.0
        if scan.is_verified:
            security_score = SecurityScore(image, scan, is_eol=is_eol, is_lts=is_lts).value
        tier = SecurityTier(scan, security_score, is_eol=is_eol)
        rem_score = RemediationScore(scan)

        analysis = ImageAnalysis(
            image=image,
            scan=scan,
            security_score=security_score,
            tier=tier.tier.value,
            remediation_score=rem_score.value,
            is_eol=is_eol,
            eol_status=eol_status,
            is_lts=is_lts,
            evidence_paths={scan.scanner: scan.evidence_path} if scan.evidence_path else {},
        )

        # The same evidence gathering `recommend` does for its finalists.
        # Without it, `analyze` and `alternatives` would report the image
        # they were asked about with every hardening fact unknown, while
        # the candidates they are compared against carry measurements --
        # and a comparison between a measurement and a blank is not one.
        if self._hardening is not None:
            digest, facts = await self._hardening.analyze(image, scan)
            if digest and not image.digest:
                image.digest = digest
            apply_facts(analysis, facts)
        finalize_verdict(analysis, cross_validated=False)
        return analysis

    async def close(self) -> None:
        """Release the scanner and the repository's connection pool.

        Not done inside `execute`, because `CompareImagesUseCase` calls it
        once per image: closing there would leave the second comparison
        talking to a client that had already been shut down.
        """
        await close_quietly(self._scanner, self._hardening, *sources_of(self._repository))

    def _parse_reference(self, reference: str) -> tuple[str, str]:
        """Repositório e tag, sem confundir a porta do registry com uma tag.

        O `rsplit(":", 1)` que morava aqui lia `registry.internal:5000/app`
        como ("registry.internal", "5000/app") e `node@sha256:...` como
        ("node@sha256", "..."). O alvo do scan sobrevivia por acidente --
        `full_reference` reconstrói a string original a partir dos dois
        pedaços errados --, mas o produto e a versão não: a consulta de
        EOL/LTS recebia o produto "registry.internal" na versão "5000", e
        `registry_host` perdia a porta. É a mesma regra que `search`,
        `recommend`, `export`, `advisor` e `alternatives` já usam.
        """
        repository, tag = split_repository_and_tag(reference)
        return repository, tag or "latest"
