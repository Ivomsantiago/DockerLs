"""De quem é cada CVE -- a resposta para "consertar o quê?".

Um relatório que diz "47 vulnerabilidades" manda consertar sem dizer o quê, e
quem lê passa a tarde descobrindo que nada no Dockerfile dela resolve o
problema. A divisão em herdadas, introduzidas e removidas leva a três ações
completamente diferentes.
"""

from __future__ import annotations

from dockerls.domain.entities.vulnerability import Severity, Vulnerability, finding_identity
from dockerls.domain.value_objects.inheritance import (
    FindingOrigin,
    attribute,
    unavailable,
)


def _v(
    cve: str, package: str, severity: Severity = Severity.HIGH, version: str = "1.0"
) -> Vulnerability:
    return Vulnerability(
        cve_id=cve, package_name=package, severity=severity, installed_version=version
    )


class TestAttribution:
    def test_achado_presente_nos_dois_e_herdado(self) -> None:
        report = attribute([_v("CVE-1", "openssl")], [_v("CVE-1", "openssl")], base_reference="b:1")

        assert [f.origin for f in report.findings] == [FindingOrigin.INHERITED]
        assert report.available

    def test_achado_so_na_imagem_final_e_seu(self) -> None:
        report = attribute([_v("CVE-2", "requests")], [], base_reference="b:1")

        assert report.introduced[0].cve_id == "CVE-2"
        assert not report.inherited

    def test_achado_que_estava_na_base_e_sumiu_e_removido(self) -> None:
        """É a medida do que o endurecimento efetivamente comprou."""
        report = attribute([], [_v("CVE-3", "zlib")], base_reference="b:1")

        assert report.removed[0].cve_id == "CVE-3"
        assert not report.introduced

    def test_a_versao_instalada_nao_entra_na_identidade(self) -> None:
        """Base e imagem final reportam o mesmo pacote com strings de versão
        normalizadas de formas diferentes; comparar isso fabricaria diferença
        a partir de formatação."""
        report = attribute(
            [_v("CVE-1", "openssl", version="3.0.11-r0")],
            [_v("CVE-1", "openssl", version="3.0.11")],
            base_reference="b:1",
        )

        assert report.inherited and not report.introduced

    def test_mesmo_cve_em_dois_pacotes_sao_dois_achados(self) -> None:
        report = attribute(
            [_v("CVE-1", "openssl"), _v("CVE-1", "libcrypto")],
            [_v("CVE-1", "openssl")],
            base_reference="b:1",
        )

        assert len(report.inherited) == 1
        assert len(report.introduced) == 1

    def test_identidade_ignora_caixa_e_espaco(self) -> None:
        assert finding_identity(_v(" cve-1 ", " OpenSSL ")) == finding_identity(
            _v("CVE-1", "openssl")
        )


class TestShare:
    def test_fracao_conta_so_o_que_esta_na_imagem(self) -> None:
        """`REMOVED` descreve o que não está lá; incluí-lo diluiria a conta com
        achados que ninguém precisa tratar."""
        report = attribute(
            [_v("CVE-1", "a"), _v("CVE-2", "b"), _v("CVE-3", "c")],
            [_v("CVE-1", "a"), _v("CVE-2", "b"), _v("CVE-9", "removido")],
            base_reference="b:1",
        )

        assert len(report.removed) == 1
        assert report.inherited_share == 2 / 3

    def test_imagem_sem_vulnerabilidade_nao_divide_por_zero(self) -> None:
        report = attribute([], [], base_reference="b:1")

        assert report.inherited_share == 0.0
        assert "no vulnerabilities" in report.explain()


class TestUnavailable:
    def test_sem_os_dois_scans_nao_ha_atribuicao(self) -> None:
        """Dizer que são suas ou da base seria inventar."""
        report = unavailable("node:22", "a base não pôde ser escaneada")

        assert not report.available
        assert not report.findings
        assert "would be inventing" in report.explain()

    def test_indisponivel_entra_no_documento_com_o_motivo(self) -> None:
        payload = unavailable("node:22", "trivy não encontrado").to_dict()

        assert payload["available"] is False
        assert payload["unavailable_reason"] == "trivy não encontrado"
        assert payload["counts"] == {"inherited": 0, "introduced": 0, "removed": 0}


class TestReport:
    def test_explicacao_responde_consertar_o_que(self) -> None:
        report = attribute(
            [_v("CVE-1", "a"), _v("CVE-2", "b")],
            [_v("CVE-1", "a")],
            base_reference="node:22-alpine",
        )

        frase = report.explain()
        assert "1 of 2 comes from the base node:22-alpine" in frase
        assert "1 comes from the layers" in frase

    def test_documento_traz_a_acao_de_cada_grupo(self) -> None:
        payload = attribute([_v("CVE-1", "a")], [], base_reference="b:1").to_dict()

        acoes = payload["actions"]
        assert "direct power over" in acoes["INTRODUCED"]  # type: ignore[index]
        assert "dockerls base" in acoes["INHERITED"]  # type: ignore[index]


def _fixable(cve: str, package: str, severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(cve_id=cve, package_name=package, severity=severity, fixed_version="9.9.9")


class TestPlan:
    """Origem sozinha diz de quem é o problema; correção diz se ele tem solução.

    Só as duas juntas dizem o que fazer na segunda-feira -- e a diferença é
    grande: se nenhuma das herdadas tem correção publicada, atualizar a base é
    trabalho perdido.
    """

    def test_separa_herdadas_com_e_sem_correcao(self) -> None:
        base = [_fixable("CVE-1", "openssl"), _v("CVE-2", "perl-base")]
        report = attribute(list(base), base, base_reference="debian:12")

        grupos = {(b.origin, b.fixable): b for b in report.plan()}

        assert grupos[(FindingOrigin.INHERITED, True)].count == 1
        assert grupos[(FindingOrigin.INHERITED, False)].count == 1

    def test_herdada_sem_correcao_manda_trocar_a_base(self) -> None:
        """Atualizar não resolve o que ninguém corrigiu."""
        base = [_v("CVE-2", "perl-base")]
        report = attribute(list(base), base, base_reference="debian:12")

        acao = report.plan()[0].action()
        assert "updating the base resolves nothing here" in acao
        assert "--alternatives" in acao

    def test_herdada_com_correcao_nao_promete_que_atualizar_resolve(self) -> None:
        """A correção existir não significa que quem publica a base já
        reconstruiu com ela."""
        base = [_fixable("CVE-1", "openssl")]
        report = attribute(list(base), base, base_reference="debian:12")

        acao = report.plan()[0].action()
        assert "may resolve it" in acao
        assert "does not mean whoever publishes the base has rebuilt" in acao

    def test_introduzida_com_correcao_manda_subir_a_dependencia(self) -> None:
        report = attribute([_fixable("CVE-3", "requests")], [], base_reference="b:1")

        assert "raise the dependency version" in report.plan()[0].action()

    def test_introduzida_sem_correcao_e_onde_uma_isencao_cabe(self) -> None:
        report = attribute([_v("CVE-4", "libfoo")], [], base_reference="b:1")

        acao = report.plan()[0].action()
        assert ".dockerls-ignore.yaml" in acao
        assert "with an expiry date" in acao

    def test_removidas_ficam_fora_do_plano(self) -> None:
        """Um plano que lista o que já não existe faz a lista parecer maior do
        que o trabalho é."""
        report = attribute([], [_v("CVE-9", "zlib")], base_reference="b:1")

        assert report.removed
        assert not report.plan()

    def test_o_grupo_com_mais_critical_abre_a_lista(self) -> None:
        """É onde a primeira hora de trabalho rende mais; ordenar por total
        faria um monte de LOW passar à frente de dois CRITICAL sem correção."""
        base = [_v("CVE-1", "a", Severity.CRITICAL), _v("CVE-2", "b", Severity.CRITICAL)]
        introduzidas = [_fixable(f"CVE-1{i}", f"p{i}", Severity.LOW) for i in range(9)]
        report = attribute([*base, *introduzidas], base, base_reference="b:1")

        primeiro = report.plan()[0]
        assert primeiro.origin is FindingOrigin.INHERITED
        assert primeiro.critical == 2

    def test_achados_do_grupo_saem_por_severidade(self) -> None:
        base = [
            _v("CVE-B", "b", Severity.LOW),
            _v("CVE-A", "a", Severity.CRITICAL),
            _v("CVE-C", "c", Severity.HIGH),
        ]
        report = attribute(list(base), base, base_reference="b:1")

        assert [f.cve_id for f in report.plan()[0].findings] == ["CVE-A", "CVE-C", "CVE-B"]


class TestFixability:
    def test_versao_corrigida_atravessa_a_atribuicao(self) -> None:
        report = attribute([_fixable("CVE-1", "openssl")], [], base_reference="b:1")

        achado = report.introduced[0]
        assert achado.fixable
        assert achado.fixed_version == "9.9.9"

    def test_versao_em_branco_nao_conta_como_corrigivel(self) -> None:
        vuln = Vulnerability(
            cve_id="CVE-1", package_name="a", severity=Severity.HIGH, fixed_version="   "
        )
        report = attribute([vuln], [], base_reference="b:1")

        assert not report.introduced[0].fixable

    def test_a_explicacao_responde_se_atualizar_a_base_adianta(self) -> None:
        base = [_fixable("CVE-1", "openssl"), _v("CVE-2", "perl-base")]
        report = attribute(list(base), base, base_reference="debian:12")

        assert "1 of the inherited has a fix published upstream" in report.explain()

    def test_o_plano_entra_no_documento(self) -> None:
        payload = attribute([_fixable("CVE-1", "a")], [], base_reference="b:1").to_dict()

        plano = payload["plan"]
        assert len(plano) == 1  # type: ignore[arg-type]
        assert plano[0]["fixable"] is True  # type: ignore[index]
        assert plano[0]["action"]  # type: ignore[index]


class TestAgreement:
    """Concordância verbal: a saída é lida por gente, e "1 vêm" é ruído."""

    def test_singular(self) -> None:
        base = [_v("CVE-1", "a")]
        frase = attribute(list(base), base, base_reference="b:1").explain()

        assert "1 of 1 comes from the base" in frase

    def test_plural(self) -> None:
        base = [_v("CVE-1", "a"), _v("CVE-2", "b")]
        frase = attribute(list(base), base, base_reference="b:1").explain()

        assert "2 of 2 come from the base" in frase

    def test_removida_no_singular(self) -> None:
        base = [_v("CVE-1", "a"), _v("CVE-9", "z")]
        frase = attribute([base[0]], base, base_reference="b:1").explain()

        assert "1 the base had was removed by the build" in frase

    def test_imagem_limpa_com_remocao_nao_esconde_a_boa_noticia(self) -> None:
        """É o melhor resultado possível, e "nada a atribuir" o escondia."""
        frase = attribute([], [_v("CVE-9", "z")], base_reference="b:1").explain()

        assert "did not survive the build" in frase
