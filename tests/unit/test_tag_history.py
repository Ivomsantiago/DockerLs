"""O histórico de digests de uma tag: o que ele conta e o que ele se recusa a contar."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.domain.value_objects.tag_history import (
    MAX_OBSERVATIONS,
    TagHistory,
    TagObservation,
    record,
)


def _at(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, tzinfo=UTC)


class TestRecord:
    def test_primeira_observacao_nao_e_movimento(self) -> None:
        history = record(TagHistory(reference="python:3.12"), "sha256:aaa", _at(1))
        assert history.moves == 0
        assert history.current_digest == "sha256:aaa"
        assert history.first_seen.startswith("2026-01-01")

    def test_mesmo_digest_observado_de_novo_nao_cria_evento(self) -> None:
        history = record(TagHistory(reference="r"), "sha256:aaa", _at(1))
        depois = record(history, "sha256:aaa", _at(5))

        assert depois is history
        assert depois.moves == 0
        assert len(depois.observations) == 1

    def test_digest_diferente_conta_como_movimento(self) -> None:
        history = record(TagHistory(reference="r"), "sha256:aaa", _at(1))
        history = record(history, "sha256:bbb", _at(3))

        assert history.moves == 1
        assert history.current_digest == "sha256:bbb"
        assert history.last_moved_at.startswith("2026-01-03")

    def test_digest_vazio_nunca_entra(self) -> None:
        """Não ter conseguido perguntar não é uma observação de nada."""
        history = record(TagHistory(reference="r"), "sha256:aaa", _at(1))
        depois = record(history, "   ", _at(2))

        assert depois is history
        assert depois.moves == 0

    def test_historico_vazio_nao_finge_estabilidade(self) -> None:
        history = TagHistory(reference="r")
        assert history.is_empty
        assert history.moves == 0
        assert history.current_digest == ""
        assert history.last_moved_at == ""
        assert "não há histórico" in history.explain()

    def test_tag_que_nunca_mudou_diz_que_o_passado_e_desconhecido(self) -> None:
        history = record(TagHistory(reference="r"), "sha256:aaa", _at(1))
        assert "desconhecido, não ausente" in history.explain()

    def test_poda_preserva_a_primeira_observacao(self) -> None:
        """Perder a primeira apagaria o "desde quando", e a contagem viraria um
        número sem unidade."""
        history = TagHistory(reference="r")
        for i in range(1, MAX_OBSERVATIONS + 6):
            history = record(history, f"sha256:{i:03d}", _at(1))

        assert len(history.observations) == MAX_OBSERVATIONS
        assert history.observations[0].digest == "sha256:001"
        assert history.observations[-1].digest == f"sha256:{MAX_OBSERVATIONS + 5:03d}"

    def test_poda_nao_faz_a_tag_parecer_mais_estavel(self) -> None:
        """A tag que mais muda é justamente a que estoura o teto: se a poda
        fizesse a contagem regredir, ela apareceria como a mais estável."""
        history = TagHistory(reference="r")
        for i in range(1, MAX_OBSERVATIONS + 11):
            history = record(history, f"sha256:{i:03d}", _at(1))

        assert history.moves == MAX_OBSERVATIONS + 9
        assert history.dropped == 10


class TestSerialization:
    def test_ida_e_volta_preserva_a_contagem(self) -> None:
        history = TagHistory(reference="r")
        for i in range(1, MAX_OBSERVATIONS + 4):
            history = record(history, f"sha256:{i:03d}", _at(1))

        voltou = TagHistory.from_dict("r", history.to_dict())

        assert voltou.moves == history.moves
        assert voltou.dropped == history.dropped
        assert voltou.observations == history.observations

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "não é um dicionário",
            {"observations": "nem isso"},
            {"observations": [{"digest": 7}]},
            {"observations": [{"digest": "   ", "observed_at": "x"}]},
            {"observations": [None, 3, []]},
        ],
    )
    def test_conteudo_de_cache_invalido_vira_historico_vazio(self, raw: object) -> None:
        """O cache é conteúdo de fora do processo; um extra corrompido não pode
        derrubar o diagnóstico que ele deveria enriquecer."""
        history = TagHistory.from_dict("r", raw)
        assert history.is_empty
        assert history.moves == 0

    def test_dropped_negativo_do_cache_e_ignorado(self) -> None:
        history = TagHistory.from_dict("r", {"observations": [], "dropped_observations": -5})
        assert history.dropped == 0

    def test_observacao_valida_sobrevive_a_uma_invalida_ao_lado(self) -> None:
        history = TagHistory.from_dict(
            "r",
            {
                "observations": [
                    {"digest": "sha256:aaa", "observed_at": "2026-01-01T12:00:00+00:00"},
                    {"digest": None},
                ]
            },
        )
        assert history.observations == (
            TagObservation(digest="sha256:aaa", observed_at="2026-01-01T12:00:00+00:00"),
        )

    def test_explicacao_entra_no_documento(self) -> None:
        history = record(TagHistory(reference="r"), "sha256:aaa", _at(1))
        history = record(history, "sha256:bbb", _at(9))
        payload = history.to_dict()

        assert payload["moves"] == 1
        assert "1 vez" in str(payload["explanation"])
        assert len(payload["observations"]) == 2  # type: ignore[arg-type]
