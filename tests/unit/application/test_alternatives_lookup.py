"""Achar uma alternativa medida -- e recusar quando não houve medição.

O tipo de retorno é a garantia que importa: quem chama é obrigado a distinguir
"não achamos nada melhor" de "não conseguimos medir", porque as duas coisas
chegam como valores diferentes em vez de como `None`.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.alternatives_lookup import (
    AlternativeFailure,
    AlternativeSuggestion,
    best_alternative,
)
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.confidence import Confidence


def _analysis(
    name: str,
    tag: str,
    *,
    critical: int = 0,
    high: int = 0,
    score: float = 80.0,
    confidence: Confidence = Confidence.HIGH,
) -> ImageAnalysis:
    image = DockerImage(name=name, tag=tag)
    vulnerabilities = [
        Vulnerability(cve_id=f"CVE-0000-{i}", severity=Severity.CRITICAL) for i in range(critical)
    ] + [Vulnerability(cve_id=f"CVE-1111-{i}", severity=Severity.HIGH) for i in range(high)]
    return ImageAnalysis(
        image=image,
        scan=ScanResult(
            image_reference=image.full_reference,
            status=ScanStatus.OK,
            # `is_verified` exige status OK **e** carimbo de tempo: sem ele
            # este fixture descrevia um scan que não completou, e o baseline
            # da comparação valia zero sem ninguém notar.
            scan_timestamp="2026-01-01T00:00:00+00:00",
            vulnerabilities=vulnerabilities,
        ),
        security_score=score,
        tier="A",
        remediation_score=100,
        confidence=confidence,
    )


@dataclass
class _Result:
    recommendations: list[ImageAnalysis]
    alternatives: list[ImageAnalysis]


def _recommender(*candidates: ImageAnalysis) -> AsyncMock:
    mock = AsyncMock()
    mock.execute = AsyncMock(return_value=_Result(list(candidates), []))
    return mock


def _analyzer(analysis: ImageAnalysis) -> AsyncMock:
    mock = AsyncMock()
    mock.execute = AsyncMock(return_value=analysis)
    return mock


@pytest.mark.asyncio
class TestBestAlternative:
    async def test_devolve_a_primeira_candidata_recomendavel(self) -> None:
        current = _analysis("node", "22", critical=4, high=9, score=60)
        candidate = _analysis("chainguard/node", "latest", critical=0, high=1, score=95)

        result = await best_alternative(
            "node:22", analyzer=_analyzer(current), recommender=_recommender(candidate)
        )

        assert isinstance(result, AlternativeSuggestion)
        assert result.candidate.image.name == "chainguard/node"
        assert result.plan.critical_delta == -4
        assert result.improves

    async def test_imagem_atual_nao_escaneavel_e_falha_e_nao_ausencia(self) -> None:
        """Sem baseline medido não há como afirmar que outra é melhor."""
        analyzer = AsyncMock()
        analyzer.execute = AsyncMock(side_effect=RuntimeError("trivy não encontrado"))

        result = await best_alternative("node:22", analyzer=analyzer, recommender=_recommender())

        assert isinstance(result, AlternativeFailure)
        assert "technical failure" in result.reason

    async def test_scan_que_nao_completou_nao_vira_baseline(self) -> None:
        """A falha chega sem exceção, e continua sendo falha.

        `AnalyzeImageUseCase` deixou de levantar para um scan que não
        completou e passou a devolver `ImageAnalysis` com score 0.0 e tier
        F. Aceitá-lo aqui faria toda candidata aparecer como uma melhora de
        ~95 pontos sobre uma imagem que ninguém mediu.
        """
        unscannable = ImageAnalysis(
            image=DockerImage(name="node", tag="22"),
            scan=ScanResult(
                image_reference="node:22",
                status=ScanStatus.ERROR,
                error_message="manifest unknown",
            ),
            security_score=0.0,
            tier="F",
            remediation_score=0,
        )
        candidate = _analysis("chainguard/node", "latest", critical=0, score=95)

        result = await best_alternative(
            "node:22",
            analyzer=_analyzer(unscannable),
            recommender=_recommender(candidate),
        )

        assert isinstance(result, AlternativeFailure)
        assert "technical failure" in result.reason

    async def test_busca_que_falha_e_reportada_como_falha(self) -> None:
        recommender = AsyncMock()
        recommender.execute = AsyncMock(side_effect=RuntimeError("rede indisponível"))

        result = await best_alternative(
            "node:22",
            analyzer=_analyzer(_analysis("node", "22")),
            recommender=recommender,
        )

        assert isinstance(result, AlternativeFailure)
        assert "failed" in result.reason

    async def test_nenhuma_candidata_recomendavel_e_falha_explicada(self) -> None:
        """Confiança baixa não vira sugestão: seria transferir a incerteza
        para quem faz a migração sem dizer que ela existe."""
        candidate = _analysis("outra", "1", confidence=Confidence.UNVERIFIED, critical=0, score=99)

        result = await best_alternative(
            "node:22",
            analyzer=_analyzer(_analysis("node", "22")),
            recommender=_recommender(candidate),
        )

        assert isinstance(result, AlternativeFailure)
        assert "enough confidence" in result.reason

    async def test_a_propria_imagem_nao_e_sugerida_como_alternativa(self) -> None:
        current = _analysis("node", "22")

        result = await best_alternative(
            "node:22", analyzer=_analyzer(current), recommender=_recommender(current)
        )

        assert isinstance(result, AlternativeFailure)

    async def test_alternativa_pior_e_reportada_em_vez_de_escondida(self) -> None:
        """Filtrar o que ficou pior transformaria a lista num argumento."""
        current = _analysis("node", "22", critical=0, high=0, score=95)
        candidate = _analysis("outra", "1", critical=3, high=5, score=40)

        result = await best_alternative(
            "node:22", analyzer=_analyzer(current), recommender=_recommender(candidate)
        )

        assert isinstance(result, AlternativeSuggestion)
        assert not result.improves
        assert result.plan.critical_delta == 3

    async def test_score_melhor_com_mais_critical_nao_conta_como_melhora(self) -> None:
        """Seria uma melhora no papel: o que decide na prática é CVE a menos."""
        current = _analysis("node", "22", critical=1, high=0, score=50)
        candidate = _analysis("outra", "1", critical=2, high=0, score=90)

        result = await best_alternative(
            "node:22", analyzer=_analyzer(current), recommender=_recommender(candidate)
        )

        assert isinstance(result, AlternativeSuggestion)
        assert not result.improves


@pytest.mark.asyncio
class TestReferenceParsing:
    async def test_digest_e_tag_sao_removidos_para_a_busca(self) -> None:
        recommender = _recommender()
        await best_alternative(
            "node:22@sha256:aa",
            analyzer=_analyzer(_analysis("node", "22")),
            recommender=recommender,
        )

        recommender.execute.assert_awaited_once_with("node")

    async def test_porta_do_host_nao_e_confundida_com_tag(self) -> None:
        recommender = _recommender()
        await best_alternative(
            "registry:5000/app",
            analyzer=_analyzer(_analysis("app", "latest")),
            recommender=recommender,
        )

        recommender.execute.assert_awaited_once_with("registry:5000/app")
