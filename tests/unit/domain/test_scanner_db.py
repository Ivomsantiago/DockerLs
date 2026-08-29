"""Guard: conferir que o scanner existe não é conferir que ele mede.

Um Trivy com base de três semanas produz um scan limpo, verde e sem erro
nenhum que simplesmente não conhece os CVEs do último mês. É a falha de
medição mais silenciosa que existe neste projeto -- nada no relatório
indica que a resposta está velha -- e é o tema central da ferramenta
aplicado ao próprio medidor.

O que estes testes travam, acima de tudo: **não conseguir ler a data não é
a base estar fresca**.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dockerls.domain.value_objects.scanner_db import (
    DatabaseState,
    classify,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _at(hours: float):
    return classify("trivy", NOW - timedelta(hours=hours), now=NOW)


class TestTheScale:
    @pytest.mark.parametrize("hours", [0, 1, 23.9, 24])
    def test_within_a_day_is_fresh(self, hours: float):
        assert _at(hours).state is DatabaseState.FRESH

    @pytest.mark.parametrize("hours", [24.1, 48, 72])
    def test_between_one_and_three_days_is_aging(self, hours: float):
        assert _at(hours).state is DatabaseState.AGING

    @pytest.mark.parametrize("hours", [72.1, 24 * 21])
    def test_beyond_three_days_is_stale(self, hours: float):
        assert _at(hours).state is DatabaseState.STALE

    def test_aging_is_still_a_usable_measurement(self):
        """Envelhecida ainda mede: a maioria dos CVEs de uma imagem é
        antiga. O que ela deixa de conhecer é o que se publicou desde."""
        assert _at(48).is_usable_measurement is True

    def test_stale_is_not(self):
        assert _at(24 * 21).is_usable_measurement is False


class TestAbsenceIsNotFreshness:
    def test_no_date_is_unknown_and_not_fresh(self):
        verdict = classify("trivy", None, detail="metadata.json is not there")
        assert verdict.state is DatabaseState.UNKNOWN

    def test_unknown_is_not_a_usable_measurement(self):
        """A pergunta é "dá para confiar na atualidade desta base". "Não
        sei" não é sim."""
        assert classify("trivy", None).is_usable_measurement is False

    def test_the_explanation_says_it_is_not_the_same_as_up_to_date(self):
        text = classify("trivy", None, detail="no metadata").explain()
        assert "not the same as up to date" in text

    def test_the_reason_survives_into_the_explanation(self):
        text = classify("grype", None, detail="metadata.json is not there").explain()
        assert "metadata.json is not there" in text


class TestClockProblems:
    def test_a_database_stamped_in_the_future_is_unknown_not_fresh(self):
        """Relógio errado numa das duas pontas. Tratá-la como fresquíssima
        esconderia o problema exatamente onde ele importa."""
        verdict = classify("trivy", NOW + timedelta(hours=5), now=NOW)

        assert verdict.state is DatabaseState.UNKNOWN
        assert "clock" in verdict.explain()

    def test_a_naive_timestamp_is_read_as_utc_instead_of_crashing(self):
        """Os dois scanners carimbam em UTC; um carimbo sem fuso é o mesmo
        instante, e recusá-lo perderia a única informação que existe."""
        naive = datetime(2026, 6, 1, 6, 0)
        assert classify("trivy", naive, now=NOW).state is DatabaseState.FRESH


class TestWhatTheHumanReads:
    def test_stale_says_what_a_scan_against_it_would_look_like(self):
        """O perigo não é o scan falhar -- é ele passar. A frase precisa
        dizer isso."""
        text = _at(24 * 21).explain()
        assert "reads exactly like a clean image and is not one" in text

    def test_the_age_is_in_days_once_it_is_days(self):
        assert "21.0 days" in _at(24 * 21).explain()

    def test_the_age_is_in_hours_while_it_is_hours(self):
        assert "30 hours" in _at(30).explain()

    def test_the_document_carries_the_state_and_the_age(self):
        payload = _at(48).to_dict()
        assert payload["state"] == "AGING"
        assert payload["age_hours"] == 48.0
        assert payload["built_at"]
