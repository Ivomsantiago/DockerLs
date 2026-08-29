"""Os achados do registry, e por que cada um é tri-estado.

Sem `UNKNOWN`, "o registry não respondeu sobre a assinatura" viraria "não há
assinatura", e as duas frases levam a decisões opostas.
"""

from __future__ import annotations

from dockerls.domain.value_objects.registry_audit import (
    AuditCheck,
    AuditFinding,
    RegistryAudit,
)
from dockerls.domain.value_objects.tristate import Tristate


class TestAlerting:
    def test_ausencia_de_assinatura_alerta(self) -> None:
        finding = AuditFinding(check=AuditCheck.SIGNATURE_PRESENT, state=Tristate.FALSE)
        assert finding.is_alert

    def test_presenca_de_assinatura_nao_alerta(self) -> None:
        finding = AuditFinding(check=AuditCheck.SIGNATURE_PRESENT, state=Tristate.TRUE)
        assert not finding.is_alert

    def test_desconhecido_nunca_alerta_e_nunca_aprova(self) -> None:
        finding = AuditFinding(check=AuditCheck.SIGNATURE_PRESENT, state=Tristate.UNKNOWN)

        assert not finding.is_alert
        assert finding.is_unmeasured
        assert "could not be" in finding.explain()

    def test_acesso_publico_e_relatado_sem_juizo(self) -> None:
        """ "Público" é o estado correto de uma imagem base oficial e o estado
        errado de um artefato interno, e a diferença é a intenção de quem
        publicou -- que esta ferramenta não tem como medir."""
        finding = AuditFinding(check=AuditCheck.PUBLICLY_READABLE, state=Tristate.TRUE)

        assert finding.is_informational
        assert not finding.is_alert
        assert "only you know that part" in finding.explain()

    def test_tag_que_ja_mudou_alerta(self) -> None:
        finding = AuditFinding(check=AuditCheck.TAG_STABLE, state=Tristate.FALSE)

        assert finding.is_alert
        assert "measured evidence" in finding.explain()

    def test_toda_checagem_explica_os_tres_estados(self) -> None:
        for check in AuditCheck:
            for state in (Tristate.TRUE, Tristate.FALSE, Tristate.UNKNOWN):
                assert AuditFinding(check=check, state=state).explain()


class TestReport:
    def test_conta_alertas_e_nao_medidos_separados(self) -> None:
        audit = RegistryAudit(
            reference="app:1",
            findings=(
                AuditFinding(check=AuditCheck.SIGNATURE_PRESENT, state=Tristate.FALSE),
                AuditFinding(check=AuditCheck.TAG_STABLE, state=Tristate.UNKNOWN),
                AuditFinding(check=AuditCheck.PINNED_REFERENCE, state=Tristate.TRUE),
            ),
        )

        assert len(audit.alerts) == 1
        assert len(audit.unmeasured) == 1
        assert "1 not measured" in audit.summary()

    def test_sem_achados_o_resumo_nao_finge_sucesso(self) -> None:
        assert "nothing could be established" in RegistryAudit(reference="x").summary()

    def test_o_relatorio_diz_o_que_nao_le(self) -> None:
        caveat = RegistryAudit(reference="x").caveat()

        assert "no cloud credential" in caveat
        assert "IAM" in caveat

    def test_documento_traz_cada_achado(self) -> None:
        audit = RegistryAudit(
            reference="app:1",
            digest="sha256:aa",
            findings=(AuditFinding(check=AuditCheck.RESOLVABLE, state=Tristate.TRUE),),
        )
        payload = audit.to_dict()

        assert payload["digest"] == "sha256:aa"
        assert payload["findings"][0]["check"] == "RESOLVABLE"  # type: ignore[index]
        assert payload["caveat"]
