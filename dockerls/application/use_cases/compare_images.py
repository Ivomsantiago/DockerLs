from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.application.dto.analysis import (
    ComparisonResult,
    ImageAnalysis,
    UnverifiedImage,
)
from dockerls.application.services.teardown import close_quietly

if TYPE_CHECKING:
    from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
    from dockerls.domain.entities.vulnerability import Vulnerability


class CompareImagesUseCase:
    def __init__(self, analyze_use_case: AnalyzeImageUseCase):
        self._analyze = analyze_use_case

    async def execute(self, references: list[str]) -> ComparisonResult:
        try:
            return await self._compare(references)
        finally:
            # The inner use case holds the scanner and the repository's
            # connection pool; it cannot release them itself because it is
            # called once per image.
            await close_quietly(self._analyze)

    async def _compare(self, references: list[str]) -> ComparisonResult:
        # A separação acontece aqui, antes de qualquer conta: uma imagem que
        # não pôde ser escaneada não tem score para comparar, e deixá-la
        # entrar no `max()` abaixo permitia que ela fosse *escolhida* como
        # vencedora contra um campo de imagens igualmente não medidas -- ou,
        # pior, que servisse de piso para o delta de quem foi medido.
        analyses: list[ImageAnalysis] = []
        unverified: list[UnverifiedImage] = []
        for ref in references:
            analysis = await self._analyze.execute(ref)
            if analysis.scan.is_verified:
                analyses.append(analysis)
                continue
            unverified.append(
                UnverifiedImage(
                    image_reference=analysis.image.full_reference or ref,
                    status=analysis.scan.status.value,
                    reason=analysis.scan.error_message or "no details",
                    kind=analysis.scan.error_kind.value,
                )
            )

        if not analyses:
            return ComparisonResult(images=[], unverified=unverified)

        winner = max(analyses, key=lambda a: a.security_score)

        all_cve_sets: list[set[str]] = []
        cve_map: dict[str, Vulnerability] = {}
        for a in analyses:
            cve_ids: set[str] = set()
            for v in a.scan.vulnerabilities:
                cve_ids.add(v.cve_id)
                cve_map[v.cve_id] = v
            all_cve_sets.append(cve_ids)

        common_ids = set.intersection(*all_cve_sets) if all_cve_sets else set()
        common_vulns = [cve_map[cid] for cid in common_ids if cid in cve_map]

        unique_vulns: dict[str, list[Vulnerability]] = {}
        for a, cve_ids_set in zip(analyses, all_cve_sets, strict=True):
            unique_ids = cve_ids_set - common_ids
            unique_vulns[a.image.full_reference] = [
                cve_map[uid] for uid in unique_ids if uid in cve_map
            ]

        # Uma linha só, com vencedor, score absoluto e delta misturados e
        # separados por ponto e vírgula, produzia
        # `...; node:22-bookworm-slim: -36.0 points` -- em que o `-36.0` lê
        # como um score negativo em vez de uma diferença. Os dados vão
        # estruturados; quem renderiza decide o formato.
        return ComparisonResult(
            images=analyses,
            winner=winner.image.full_reference,
            summary=(
                f"{winner.image.full_reference} scores highest "
                f"({winner.security_score}, tier {winner.tier})"
            ),
            common_vulns=common_vulns,
            unique_vulns=unique_vulns,
            unverified=unverified,
        )
