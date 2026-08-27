"""Guard: emitir VEX não pode virar inventar uma alegação técnica.

Quase toda implementação de "exporte suas isenções como VEX" comete o mesmo
erro: emite tudo como `not_affected`. Mas `not_affected` é uma afirmação
**técnica** -- o código vulnerável não está presente, ou não é alcançável,
ou já está mitigado --, e o padrão exige dizer qual das cinco razões é.

Uma justificativa em texto livre como "a equipe aceitou o risco até o Q3"
não é nenhuma das cinco. Traduzi-la para `not_affected` transformaria uma
decisão de risco numa afirmação que ninguém fez -- e, pior, uma afirmação
que outra ferramenta vai *acreditar*, porque VEX existe para ser acreditado.

É esse limite que estes testes guardam.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from dockerls.domain.value_objects.vex import (
    OPENVEX_CONTEXT,
    ExemptionInput,
    VexJustification,
    VexStatus,
    build_document,
    parse_justification,
    statement_for,
)


class TestRiskAcceptanceIsNeverANotAffectedClaim:
    def test_a_free_text_reason_produces_affected(self):
        exemption = ExemptionInput(cve="CVE-1", justification="risk accepted until Q3")

        statement = statement_for(exemption)

        assert statement.status is VexStatus.AFFECTED
        assert statement.justification is None

    def test_the_human_reason_survives_in_the_action_statement(self):
        """O consumidor precisa ver *por que* a exceção existe. Perder o
        texto tornaria o documento uma lista de CVEs sem decisão nenhuma."""
        exemption = ExemptionInput(cve="CVE-1", justification="risk accepted until Q3")

        assert "risk accepted until Q3" in statement_for(exemption).action_statement

    def test_an_exemption_with_no_reason_says_so(self):
        """Um `action_statement` vazio faria a exceção parecer justificada."""
        statement = statement_for(ExemptionInput(cve="CVE-1"))

        assert statement.status is VexStatus.AFFECTED
        assert "no reason given" in statement.action_statement

    def test_a_declared_standard_justification_produces_not_affected(self):
        """Quando alguém *declara* a alegação técnica, ela vale -- a
        ferramenta não a inventou, só a transmitiu."""
        exemption = ExemptionInput(
            cve="CVE-1",
            justification="the function is not compiled in",
            vex_justification="vulnerable_code_not_present",
        )

        statement = statement_for(exemption)

        assert statement.status is VexStatus.NOT_AFFECTED
        assert statement.justification is VexJustification.VULNERABLE_CODE_NOT_PRESENT

    @pytest.mark.parametrize("justification", list(VexJustification))
    def test_every_standard_justification_is_accepted(self, justification: VexJustification):
        exemption = ExemptionInput(cve="CVE-1", vex_justification=str(justification))
        assert statement_for(exemption).status is VexStatus.NOT_AFFECTED

    def test_a_justification_outside_the_vocabulary_is_not_one(self):
        assert parse_justification("we looked at it and it is fine") is None
        assert parse_justification("") is None


class TestTheExpiryDateSurvives:
    def test_it_is_written_into_the_action_statement(self):
        """VEX não tem campo para expiração, e uma isenção sem prazo visível
        é uma isenção que ninguém revisa."""
        exemption = ExemptionInput(cve="CVE-1", justification="accepted", expires=date(2099, 1, 1))

        assert "expires on 2099-01-01" in statement_for(exemption).action_statement

    def test_it_survives_even_on_a_not_affected_statement(self):
        exemption = ExemptionInput(
            cve="CVE-1",
            vex_justification="component_not_present",
            expires=date(2099, 1, 1),
        )

        assert "expires on 2099-01-01" in statement_for(exemption).action_statement

    def test_no_expiry_adds_nothing(self):
        statement = statement_for(ExemptionInput(cve="CVE-1", justification="accepted"))
        assert "expires" not in statement.action_statement


class TestTheDocument:
    def _document(self, **kwargs):
        return build_document(
            [ExemptionInput(cve="CVE-1", justification="accepted")],
            products=["pkg:oci/app@sha256:aa"],
            author="Security <sec@example.com>",
            **kwargs,
        )

    def test_it_declares_the_context_version_it_speaks(self):
        """Sem `@context` o consumidor não sabe qual vocabulário ler."""
        assert self._document().to_dict()["@context"] == OPENVEX_CONTEXT

    def test_it_names_an_author(self):
        assert self._document().to_dict()["author"] == "Security <sec@example.com>"

    def test_every_statement_carries_the_product(self):
        payload = self._document().to_dict()
        assert payload["statements"][0]["products"] == [{"@id": "pkg:oci/app@sha256:aa"}]

    def test_the_id_is_stable_for_the_same_content(self):
        first = self._document(timestamp="2026-01-01T00:00:00+00:00").to_dict()["@id"]
        second = self._document(timestamp="2026-01-01T00:00:00+00:00").to_dict()["@id"]
        assert first == second

    def test_the_id_changes_when_the_content_does(self):
        """Dois documentos diferentes com o mesmo `@id` fariam um consumidor
        tratar um como revisão do outro."""
        stamp = "2026-01-01T00:00:00+00:00"
        one = self._document(timestamp=stamp).to_dict()["@id"]
        other = build_document(
            [ExemptionInput(cve="CVE-2", justification="accepted")],
            products=["pkg:oci/app@sha256:aa"],
            author="Security <sec@example.com>",
            timestamp=stamp,
        ).to_dict()["@id"]
        assert one != other

    def test_it_serialises_to_valid_json(self):
        assert json.loads(self._document().to_json())["version"] == 1

    def test_an_empty_exemption_list_is_an_empty_document_not_a_crash(self):
        document = build_document([], products=["pkg:oci/app"], author="Someone")
        assert document.to_dict()["statements"] == []
