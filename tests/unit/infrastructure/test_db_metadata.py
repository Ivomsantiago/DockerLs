"""Guard: ler a data da base nunca levanta, e nunca inventa.

Todo caminho de falha -- arquivo ausente, JSON quebrado, campo com outro
nome, carimbo ilegível -- devolve `(None, motivo)`. O motivo importa tanto
quanto o `None`: sem ele o `doctor` diria "idade desconhecida" sem dizer
por quê, e ninguém saberia se é um scanner recém-instalado ou um cache
corrompido.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from dockerls.infrastructure.toolchain.db_metadata import (
    read_grype_built_at,
    read_trivy_built_at,
)

if TYPE_CHECKING:
    from pathlib import Path


def _trivy(tmp_path: Path, payload: object) -> Path:
    db = tmp_path / "db"
    db.mkdir(parents=True, exist_ok=True)
    (db / "metadata.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def _grype(tmp_path: Path, payload: object, schema: str = "5") -> Path:
    db = tmp_path / "db" / schema
    db.mkdir(parents=True, exist_ok=True)
    (db / "metadata.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


class TestTrivy:
    def test_it_reads_updated_at(self, tmp_path):
        built, detail = read_trivy_built_at(_trivy(tmp_path, {"UpdatedAt": "2026-06-01T10:00:00Z"}))

        assert built == datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
        assert detail == ""

    def test_a_missing_file_is_a_reason_not_a_crash(self, tmp_path):
        built, detail = read_trivy_built_at(tmp_path)

        assert built is None
        assert "is not there" in detail

    def test_broken_json_is_a_reason(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir()
        (db / "metadata.json").write_text("{not json", encoding="utf-8")

        built, detail = read_trivy_built_at(tmp_path)

        assert built is None
        assert "not valid JSON" in detail

    def test_a_document_without_the_field_is_a_reason(self, tmp_path):
        built, detail = read_trivy_built_at(_trivy(tmp_path, {"Version": 2}))

        assert built is None
        assert "carries none of" in detail

    def test_an_unparseable_timestamp_is_a_reason(self, tmp_path):
        built, detail = read_trivy_built_at(_trivy(tmp_path, {"UpdatedAt": "last tuesday"}))

        assert built is None
        assert "not a timestamp" in detail

    def test_an_oversized_file_is_refused_instead_of_read(self, tmp_path):
        """Ler sem limite um arquivo que outro processo escreveu é confiar
        demais num caminho de disco."""
        db = tmp_path / "db"
        db.mkdir()
        (db / "metadata.json").write_text("x" * (64 * 1024 + 1), encoding="utf-8")

        built, detail = read_trivy_built_at(tmp_path)

        assert built is None
        assert "larger than" in detail

    def test_extra_fractional_digits_do_not_defeat_it(self, tmp_path):
        """Alguns carimbos trazem mais de seis casas, que o
        `fromisoformat` recusa. Cortar é melhor que desistir da data."""
        built, _ = read_trivy_built_at(
            _trivy(tmp_path, {"UpdatedAt": "2026-06-01T10:00:00.123456789Z"})
        )

        assert built is not None
        assert built.year == 2026


class TestGrype:
    def test_it_reads_built(self, tmp_path):
        built, detail = read_grype_built_at(_grype(tmp_path, {"built": "2026-06-01T09:00:00Z"}))

        assert built == datetime(2026, 6, 1, 9, 0, tzinfo=UTC)
        assert detail == ""

    def test_it_picks_the_newest_schema(self, tmp_path):
        """O número do esquema muda entre versões do Grype. Fixá-lo faria a
        leitura envelhecer junto com o código."""
        _grype(tmp_path, {"built": "2020-01-01T00:00:00Z"}, schema="3")
        _grype(tmp_path, {"built": "2026-06-01T09:00:00Z"}, schema="5")

        built, _ = read_grype_built_at(tmp_path)

        assert built is not None
        assert built.year == 2026

    def test_no_database_at_all_is_a_reason(self, tmp_path):
        built, detail = read_grype_built_at(tmp_path)

        assert built is None
        assert "no metadata" in detail
