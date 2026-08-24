"""`compare` nunca pontua o que não mediu.

O bug: `dockerls compare alpine:3.24.1 alpine:99.99.99` saía com código 0 e
mostrava a tag inexistente na tabela com "Score 0.0, Tier F" -- como se
tivesse sido escaneada e tivesse ido mal. O 0.0/F é o fallback de
`AnalyzeImageUseCase` para um scan que não completou; `analyze` já o
interceptava antes de renderizar, `compare` nunca o fez.

Os quatro códigos de saída existem para que um pipeline consiga distinguir
"comparei tudo" de "comparei o que deu".
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.application.dto.analysis import ComparisonResult, ImageAnalysis, UnverifiedImage
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus

runner = CliRunner()

#: O stderr real do Trivy para uma tag inexistente, com o ruído sobre o
#: socket do Docker que não deve chegar ao terminal.
TRIVY_NOT_FOUND = (
    'FATAL image scan error: unable to find the specified image "alpine:99.99.99": '
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
)


def _verified(name: str, tag: str, score: float, tier: str) -> ImageAnalysis:
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag),
        scan=ScanResult(
            image_reference=f"{name}:{tag}",
            scan_timestamp="2026-01-01T00:00:00+00:00",
            status=ScanStatus.OK,
        ),
        security_score=score,
        tier=tier,
        remediation_score=100,
    )


def _failure(reference: str) -> UnverifiedImage:
    return UnverifiedImage(
        image_reference=reference,
        status=ScanStatus.ERROR.value,
        reason=TRIVY_NOT_FOUND,
        kind=ScanErrorKind.NOT_FOUND.value,
    )


def _run(result: ComparisonResult, *images: str):
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=result)
    with patch(
        "dockerls.cli.commands.compare.build_compare_use_case",
        AsyncMock(return_value=use_case),
    ):
        return runner.invoke(app, ["compare", *(images or ("a:1", "b:2"))])


class TestExitCodes:
    def test_every_image_measured_exits_zero(self):
        a, b = _verified("alpine", "3.24.1", 90.0, "A"), _verified("alpine", "3.23", 70.0, "C")
        result = _run(
            ComparisonResult(images=[a, b], winner=a.image.full_reference, summary="a wins")
        )

        assert result.exit_code == 0
        assert "Winner" in result.stdout
        assert "Failed" not in result.stdout

    def test_nothing_could_be_scanned_exits_one(self):
        """Compatível com o comportamento anterior para este caso: nada foi
        medido, então é falha de execução, não veredito."""
        result = _run(
            ComparisonResult(
                images=[], unverified=[_failure("alpine:99.99.99"), _failure("alpine:98.98.98")]
            )
        )

        assert result.exit_code == 1
        assert "No image could be scanned" in result.stdout
        assert "not a security verdict" in result.stdout

    def test_a_partial_comparison_exits_two(self):
        a, b = _verified("alpine", "3.24.1", 90.0, "A"), _verified("alpine", "3.23", 70.0, "C")
        result = _run(
            ComparisonResult(
                images=[a, b],
                winner=a.image.full_reference,
                summary="a wins",
                unverified=[_failure("alpine:99.99.99")],
            ),
            "alpine:3.24.1",
            "alpine:3.23",
            "alpine:99.99.99",
        )

        assert result.exit_code == 2
        assert "Partial comparison" in result.stdout

    def test_a_single_measured_image_exits_three(self):
        """Uma imagem medida não é uma comparação: mostrar a tabela com uma
        linha só sugeriria um vencedor onde não houve disputa."""
        only = _verified("alpine", "3.24.1", 90.0, "A")
        result = _run(
            ComparisonResult(
                images=[only],
                winner=only.image.full_reference,
                unverified=[_failure("alpine:99.99.99")],
            )
        )

        assert result.exit_code == 3
        assert "Not enough data to compare" in result.stdout
        assert "Winner" not in result.stdout

    def test_fewer_than_two_arguments_exits_one(self):
        assert runner.invoke(app, ["compare", "alpine:3.24.1"]).exit_code == 1


class TestUnverifiedImagesAreNeverScored:
    def test_the_failed_image_is_absent_from_the_table(self):
        """O coração do bug: nenhuma linha com score/tier para uma imagem
        que ninguém escaneou."""
        a, b = _verified("alpine", "3.24.1", 90.0, "A"), _verified("alpine", "3.23", 70.0, "C")
        result = _run(
            ComparisonResult(
                images=[a, b],
                winner=a.image.full_reference,
                unverified=[_failure("alpine:99.99.99")],
            ),
            "alpine:3.24.1",
            "alpine:3.23",
            "alpine:99.99.99",
        )
        collapsed = " ".join(result.stdout.split())

        # A referência aparece -- na seção de falhas --, mas nunca ao lado
        # de um score ou de um tier.
        assert "alpine:99.99.99" in collapsed
        assert "Failed (not compared)" in collapsed
        assert "alpine:99.99.99 NOT_FOUND" in collapsed
        assert "alpine:99.99.99 0.0" not in collapsed
        assert "Tier F" not in collapsed

    def test_the_failed_image_is_never_the_winner(self):
        a = _verified("alpine", "3.24.1", 90.0, "A")
        b = _verified("alpine", "3.23", 70.0, "C")
        result = _run(
            ComparisonResult(
                images=[a, b],
                winner=a.image.full_reference,
                unverified=[_failure("alpine:99.99.99")],
            ),
            "alpine:3.24.1",
            "alpine:3.23",
            "alpine:99.99.99",
        )
        collapsed = " ".join(result.stdout.split())

        assert "Winner: alpine:3.24.1" in collapsed

    def test_the_raw_scanner_dump_never_reaches_the_terminal(self):
        result = _run(
            ComparisonResult(images=[], unverified=[_failure("alpine:99.99.99")]),
        )

        assert "NOT_FOUND -- tag not found on the registry" in " ".join(result.stdout.split())
        assert "docker.sock" not in result.stdout


class TestUseCaseFiltersBeforeChoosingAWinner:
    """A filtragem acontece no use case, antes de qualquer conta -- não só
    na renderização. Um consumidor do `ComparisonResult` (exporter, JSON)
    tem a mesma garantia que o terminal."""

    @staticmethod
    def _analyze_returning(*analyses: ImageAnalysis):
        inner = AsyncMock()
        inner.execute = AsyncMock(side_effect=list(analyses))
        inner.close = AsyncMock()
        return inner

    @staticmethod
    def _unscanned(name: str, tag: str) -> ImageAnalysis:
        """Exatamente o que `AnalyzeImageUseCase` devolve para um scan que
        falhou: score 0.0, tier F, e `is_verified` falso."""
        return ImageAnalysis(
            image=DockerImage(name=name, tag=tag),
            scan=ScanResult(
                image_reference=f"{name}:{tag}",
                status=ScanStatus.ERROR,
                error_message=TRIVY_NOT_FOUND,
                error_kind=ScanErrorKind.NOT_FOUND,
            ),
            security_score=0.0,
            tier="F",
            remediation_score=0,
        )

    async def _compare(self, *analyses: ImageAnalysis) -> ComparisonResult:
        use_case = CompareImagesUseCase(self._analyze_returning(*analyses))
        return await use_case.execute([a.image.full_reference for a in analyses])

    async def test_an_unscanned_image_is_kept_out_of_images(self):
        good = _verified("alpine", "3.24.1", 90.0, "A")
        result = await self._compare(good, self._unscanned("alpine", "99.99.99"))

        assert [a.image.full_reference for a in result.images] == ["alpine:3.24.1"]
        assert [u.image_reference for u in result.unverified] == ["alpine:99.99.99"]
        assert result.unverified[0].kind == "NOT_FOUND"

    async def test_the_winner_is_never_an_unscanned_image(self):
        """Com todas as medidas piores que 0.0 seria impossível; o risco
        real é o inverso -- a não medida entrar no `max()` e servir de piso
        para o delta de quem foi medido."""
        low = _verified("alpine", "3.23", 5.0, "F")
        result = await self._compare(low, self._unscanned("alpine", "99.99.99"))

        assert result.winner == "alpine:3.23"
        assert all(a.scan.is_verified for a in result.images)

    async def test_no_image_measured_leaves_no_winner(self):
        result = await self._compare(
            self._unscanned("alpine", "99.99.99"), self._unscanned("alpine", "98.98.98")
        )

        assert result.images == []
        assert result.winner == ""
        assert len(result.unverified) == 2
