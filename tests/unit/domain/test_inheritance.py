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
        assert "nenhuma vulnerabilidade" in report.explain()


class TestUnavailable:
    def test_sem_os_dois_scans_nao_ha_atribuicao(self) -> None:
        """Dizer que são suas ou da base seria inventar."""
        report = unavailable("node:22", "a base não pôde ser escaneada")

        assert not report.available
        assert not report.findings
        assert "seria inventar" in report.explain()

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
        assert "1 de 2 vêm da base node:22-alpine" in frase
        assert "1 vêm das camadas" in frase

    def test_documento_traz_a_acao_de_cada_grupo(self) -> None:
        payload = attribute([_v("CVE-1", "a")], [], base_reference="b:1").to_dict()

        acoes = payload["actions"]
        assert "poder direto" in acoes["INTRODUCED"]  # type: ignore[index]
        assert "dockerls base" in acoes["INHERITED"]  # type: ignore[index]
