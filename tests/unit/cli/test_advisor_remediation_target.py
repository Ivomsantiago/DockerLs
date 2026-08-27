"""O Remediation Plan é sobre a imagem que o usuário nomeou.

O bug: `dockerls advisor eclipse-temurin:21-jre-alpine` -- um JRE Alpine --
respondia com "STEP 1: Update stdlib (go1.26.5 -> 1.25.13)" e o identificador
`GO-2026-1234`, formato da Go Vulnerability Database. Não existe stdlib Go
dentro de um JRE, e o CVE real da imagem não aparecia em lugar nenhum.

A causa não era filtro de saída: o plano nascia de `best` -- a candidata que
a busca por *repositório* elegeu -- em vez da imagem pedida. Quando a busca
devolvia uma candidata de outro ecossistema, o plano descrevia as CVEs dela
sob o título da imagem do usuário.

Os testes abaixo cruzam os dois sentidos: uma imagem Java com uma candidata
Go, e uma imagem Go com uma candidata Java. Nenhum dos dois planos pode citar
o ecossistema do outro.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability

runner = CliRunner()


def _analysis(name: str, tag: str, vulnerabilities: list[Vulnerability]) -> ImageAnalysis:
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag),
        scan=ScanResult(
            image_reference=f"{name}:{tag}",
            vulnerabilities=vulnerabilities,
            scan_timestamp="2026-01-01T00:00:00+00:00",
            status=ScanStatus.OK,
        ),
        security_score=80.0,
        tier="B",
        remediation_score=100,
    )


def _java_image() -> ImageAnalysis:
    """Um JRE com um achado de JRE: pacote e versão que só existem em Java."""
    return _analysis(
        "eclipse-temurin",
        "21-jre-alpine",
        [
            Vulnerability(
                cve_id="CVE-2026-21001",
                severity=Severity.HIGH,
                package_name="openjdk-jre",
                installed_version="21.0.1+12",
                fixed_version="21.0.2+13",
            )
        ],
    )


def _go_image() -> ImageAnalysis:
    """Uma imagem Go com o achado que apareceu, indevidamente, no relatório
    do JRE: `stdlib` e um identificador da Go Vulnerability Database."""
    return _analysis(
        "golang",
        "1.26-alpine",
        [
            Vulnerability(
                cve_id="GO-2026-1234",
                severity=Severity.HIGH,
                package_name="stdlib",
                installed_version="go1.26.5",
                fixed_version="1.25.13",
            )
        ],
    )


def _run(requested: str, current: ImageAnalysis | None, candidate: ImageAnalysis):
    """Roda o advisor com a busca devolvendo `candidate` e o scan da imagem
    pedida devolvendo `current`."""
    search = AsyncMock()
    search.execute = AsyncMock(
        return_value=AnalysisResult(
            query=requested.split(":")[0],
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[candidate],
        )
    )
    analyzer = AsyncMock()
    analyzer.execute = AsyncMock(return_value=current)
    analyzer.close = AsyncMock()

    with (
        patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case",
            AsyncMock(return_value=search),
        ),
        patch(
            "dockerls.cli.commands.advisor.build_analyze_use_case",
            AsyncMock(return_value=analyzer),
        ),
    ):
        return runner.invoke(app, ["advisor", requested, "--no-color"])


def _plan(output: str) -> str:
    """Só o Remediation Plan, sem a seção de migração acima dele.

    A migração cita as duas imagens por definição -- é o que ela é --, então
    varrer a saída inteira acusaria a migração como se fosse o plano.
    """
    collapsed = " ".join(output.split())
    marker = "Remediation Plan"
    assert marker in collapsed, f"sem Remediation Plan na saida: {collapsed[:300]}"
    return collapsed[collapsed.index(marker) :]


class TestPlanNeverCrossesEcosystems:
    def test_a_java_image_gets_java_steps_not_go_steps(self):
        """O caso relatado, literal: JRE Alpine cujo plano falava de stdlib Go."""
        result = _run("eclipse-temurin:21-jre-alpine", _java_image(), _go_image())
        plan = _plan(result.output)

        assert "CVE-2026-21001" in plan
        assert "openjdk-jre" in plan
        assert "21.0.1+12" in plan and "21.0.2+13" in plan

        assert "GO-2026-1234" not in plan
        assert "go1.26.5" not in plan
        assert "stdlib" not in plan

    def test_a_go_image_gets_go_steps_not_java_steps(self):
        """O sentido inverso, para que a correção não seja um filtro que
        apenas favorece Java."""
        result = _run("golang:1.26-alpine", _go_image(), _java_image())
        plan = _plan(result.output)

        assert "GO-2026-1234" in plan
        assert "stdlib" in plan
        assert "go1.26.5" in plan and "1.25.13" in plan

        assert "CVE-2026-21001" not in plan
        assert "openjdk-jre" not in plan

    def test_the_plan_names_the_image_it_addresses(self):
        """Um plano que cita versões de pacote precisa dizer de qual imagem
        elas vieram -- o relatório carrega duas imagens ao mesmo tempo."""
        result = _run("eclipse-temurin:21-jre-alpine", _java_image(), _go_image())

        assert "Remediation Plan for eclipse-temurin:21-jre-alpine" in " ".join(
            result.output.split()
        )

    @pytest.mark.parametrize(
        ("requested", "current", "candidate", "expected_cve", "forbidden_cve"),
        [
            (
                "eclipse-temurin:21-jre-alpine",
                "java",
                "go",
                "CVE-2026-21001",
                "GO-2026-1234",
            ),
            ("golang:1.26-alpine", "go", "java", "GO-2026-1234", "CVE-2026-21001"),
        ],
    )
    def test_json_output_carries_the_same_target(
        self, requested, current, candidate, expected_cve, forbidden_cve
    ):
        """A garantia vale para quem consome `--format json`, não só para o
        terminal: um pipeline que lê o campo `remediation` recebe os passos
        da imagem pedida."""
        import json

        images = {"java": _java_image(), "go": _go_image()}
        search = AsyncMock()
        search.execute = AsyncMock(
            return_value=AnalysisResult(
                query=requested.split(":")[0],
                total_tags_scanned=1,
                total_tags_analyzed=1,
                baseline_met=True,
                recommendations=[images[candidate]],
            )
        )
        analyzer = AsyncMock()
        analyzer.execute = AsyncMock(return_value=images[current])
        analyzer.close = AsyncMock()

        with (
            patch(
                "dockerls.cli.commands.advisor.build_recommend_use_case",
                AsyncMock(return_value=search),
            ),
            patch(
                "dockerls.cli.commands.advisor.build_analyze_use_case",
                AsyncMock(return_value=analyzer),
            ),
        ):
            result = runner.invoke(app, ["advisor", requested, "--format", "json"])

        payload = json.loads(result.output)
        assert payload["remediation_target"] == requested
        steps = json.dumps(payload["remediation"])
        assert expected_cve in steps
        assert forbidden_cve not in steps


class TestTheInsightsFollowTheSameTarget:
    """As particularidades de ecossistema seguem o **alvo do plano**, e não
    a raiz do documento.

    A alternativa era segui-la a `best`, e ela produzia a mesma confusão que
    o P1 do Remediation Plan: conselho sobre Debian ao lado de uma
    recomendação Alpine, sem nada dizendo que são imagens diferentes. A
    escolha aqui é deliberada e o JSON a declara -- `ecosystem_insights.for`
    nomeia de quem o conselho é --, e é isso que estes testes travam.
    """

    def test_the_insights_describe_the_image_the_user_named(self):
        import json

        search = AsyncMock()
        search.execute = AsyncMock(
            return_value=AnalysisResult(
                query="eclipse-temurin",
                total_tags_scanned=1,
                total_tags_analyzed=1,
                baseline_met=True,
                # A candidata eleita é Go: se as particularidades seguissem
                # a raiz do documento, o usuário leria conselho de Go sobre
                # a imagem Java que ele nomeou.
                recommendations=[_go_image()],
            )
        )
        analyzer = AsyncMock()
        analyzer.execute = AsyncMock(return_value=_java_image())
        analyzer.close = AsyncMock()

        with (
            patch(
                "dockerls.cli.commands.advisor.build_recommend_use_case",
                AsyncMock(return_value=search),
            ),
            patch(
                "dockerls.cli.commands.advisor.build_analyze_use_case",
                AsyncMock(return_value=analyzer),
            ),
        ):
            result = runner.invoke(
                app, ["advisor", "eclipse-temurin:21-jre-alpine", "--format", "json"]
            )

        payload = json.loads(result.output)
        insights = payload["ecosystem_insights"]
        assert insights["for"] == payload["remediation_target"]
        assert insights["for"] == "eclipse-temurin:21-jre-alpine"
        assert "java" in insights["ecosystem"].lower()

    def test_the_document_says_whose_advice_it_is(self):
        """`best` fica na raiz e o alvo fica ao lado. Sem o campo `for`, um
        consumidor não teria como saber que são imagens diferentes."""
        import json

        search = AsyncMock()
        search.execute = AsyncMock(
            return_value=AnalysisResult(
                query="eclipse-temurin",
                total_tags_scanned=1,
                total_tags_analyzed=1,
                baseline_met=True,
                recommendations=[_go_image()],
            )
        )
        analyzer = AsyncMock()
        analyzer.execute = AsyncMock(return_value=_java_image())
        analyzer.close = AsyncMock()

        with (
            patch(
                "dockerls.cli.commands.advisor.build_recommend_use_case",
                AsyncMock(return_value=search),
            ),
            patch(
                "dockerls.cli.commands.advisor.build_analyze_use_case",
                AsyncMock(return_value=analyzer),
            ),
        ):
            result = runner.invoke(
                app, ["advisor", "eclipse-temurin:21-jre-alpine", "--format", "json"]
            )

        payload = json.loads(result.output)
        # A raiz continua sendo a candidata eleita, e o campo `for` é o que
        # impede ler as duas como se fossem a mesma imagem.
        assert payload["image"]["full_reference"] != payload["ecosystem_insights"]["for"]


class TestBareNameKeepsTheOriginalBehaviour:
    """Sem tag na linha de comando não existe imagem atual, e aconselhar
    sobre a melhor candidata é o que o comando sempre fez."""

    def test_a_bare_repository_advises_on_the_best_candidate(self):
        candidate = _go_image()
        search = AsyncMock()
        search.execute = AsyncMock(
            return_value=AnalysisResult(
                query="golang",
                total_tags_scanned=1,
                total_tags_analyzed=1,
                baseline_met=True,
                recommendations=[candidate],
            )
        )
        with patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case",
            AsyncMock(return_value=search),
        ):
            result = runner.invoke(app, ["advisor", "golang", "--no-color"])

        plan = _plan(result.output)
        assert "GO-2026-1234" in plan
        assert "Remediation Plan for golang:1.26-alpine" in plan

    def test_an_unmeasurable_current_image_falls_back_to_the_candidate(self):
        """Se o scan da imagem pedida falhar, `current` é None e o plano
        volta a ser sobre a candidata -- com o cabeçalho dizendo isso, para
        que ninguém leia os passos como sendo da imagem que pediu."""
        unscanned = ImageAnalysis(
            image=DockerImage(name="eclipse-temurin", tag="21-jre-alpine"),
            scan=ScanResult(
                image_reference="eclipse-temurin:21-jre-alpine", status=ScanStatus.ERROR
            ),
            security_score=0.0,
            tier="F",
            remediation_score=0,
        )
        result = _run("eclipse-temurin:21-jre-alpine", unscanned, _go_image())
        plan = _plan(result.output)

        assert "Remediation Plan for golang:1.26-alpine" in plan
