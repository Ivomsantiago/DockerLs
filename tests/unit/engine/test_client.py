"""Guard: nada que a engine devolva pode derrubar o comando.

O documento chega de um processo separado, então tudo nele é entrada
externa: um campo faltando, um tipo inesperado, uma contagem que não bate,
uma resposta que nem é JSON. A regra é sempre a mesma -- devolver `None` e
deixar o pipeline Python responder --, porque uma otimização que pode
derrubar o comando não vale o ganho.
"""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

import pytest

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanStatus
from dockerls.domain.entities.vulnerability import Severity
from dockerls.integrations.engine.client import EngineClient, EngineTarget
from dockerls.integrations.engine.locator import PROTOCOL_VERSION

if TYPE_CHECKING:
    from pathlib import Path

TARGETS = [EngineTarget(reference="node:22", dedup_key="sha256:aaa")]


def fake_engine(tmp_path: Path, body: str) -> str:
    """Um script que se passa pela engine. O que está sob teste é a
    fronteira entre processos, e um duplo em Python não a atravessaria."""
    path = tmp_path / "fake-engine"
    path.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def client_for(tmp_path: Path, body: str, **kwargs) -> EngineClient:
    return EngineClient(
        engine_path=fake_engine(tmp_path, body),
        scanner_path="/usr/bin/trivy",
        timeout_seconds=kwargs.get("timeout_seconds", 5.0),
        skip_db_update=True,
        raw_dir=None,
    )


def answer(**overrides) -> str:
    payload = {
        "version": PROTOCOL_VERSION,
        "results": [
            {
                "image_reference": "node:22",
                "scanner": "trivy",
                "vulnerabilities": [],
                "scan_timestamp": "2026-01-01T00:00:00+00:00",
                "status": "OK",
                "error_message": "",
                "error_kind": "NONE",
                "os_family": "alpine",
                "os_version": "3.21",
                "raw_path": "",
            }
        ],
        "metrics": {"scans_performed": 1, "duplicates_collapsed": 0, "wall_seconds": 1.5},
    }
    payload.update(overrides)
    return json.dumps(payload)


def emit(document: str) -> str:
    return f"cat <<'ENGINEOUT'\n{document}\nENGINEOUT\n"


class TestAGoodAnswer:
    @pytest.mark.asyncio
    async def test_is_decoded_into_domain_objects(self, tmp_path):
        client = client_for(tmp_path, emit(answer()))
        outcome = await client.scan_batch(TARGETS, workers=2, cache_dirs=[])

        assert outcome is not None
        assert len(outcome.results) == 1
        result = outcome.results[0]
        assert result.status is ScanStatus.OK
        assert result.is_verified is True
        assert result.os_family == "alpine"
        assert outcome.scans_performed == 1
        assert outcome.wall_seconds == 1.5

    @pytest.mark.asyncio
    async def test_an_empty_batch_never_starts_a_process(self, tmp_path):
        client = client_for(tmp_path, "exit 1\n")
        outcome = await client.scan_batch([], workers=2, cache_dirs=[])
        assert outcome is not None
        assert outcome.results == []


class TestAnAnswerThatCannotBeTrusted:
    @pytest.mark.asyncio
    async def test_a_protocol_mismatch_falls_back(self, tmp_path):
        client = client_for(tmp_path, emit(answer(version=999)))
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_a_fatal_error_falls_back(self, tmp_path):
        client = client_for(tmp_path, emit(answer(fatal_error="request is not valid JSON")))
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_a_result_count_that_does_not_match_falls_back(self, tmp_path):
        """Alinhar por posição é o que liga cada resultado ao alvo pedido.
        Uma contagem diferente não é um lote parcial, é um alinhamento que
        deixou de existir -- e usá-lo atribuiria a medição de uma imagem a
        outra."""
        client = client_for(tmp_path, emit(answer(results=[])))
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_output_that_is_not_json_falls_back(self, tmp_path):
        client = client_for(tmp_path, "echo 'not json'\n")
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_a_json_document_that_is_not_an_object_falls_back(self, tmp_path):
        client = client_for(tmp_path, emit("[1, 2, 3]"))
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_a_non_zero_exit_falls_back(self, tmp_path):
        client = client_for(tmp_path, "echo boom >&2\nexit 2\n")
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_a_missing_binary_falls_back(self, tmp_path):
        client = EngineClient(
            engine_path=str(tmp_path / "absent"),
            scanner_path="/usr/bin/trivy",
            timeout_seconds=5.0,
            skip_db_update=False,
            raw_dir=None,
        )
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None

    @pytest.mark.asyncio
    async def test_an_engine_that_hangs_is_killed_and_falls_back(self, tmp_path, monkeypatch):
        # A folga sobre a soma dos timeouts individuais existe para cobrir
        # a engine travando sem medir nada; aqui ela é encurtada para que
        # o teste prove o mesmo caminho em um segundo em vez de trinta.
        monkeypatch.setattr("dockerls.integrations.engine.client._ENGINE_OVERHEAD_SECONDS", 0.5)
        client = client_for(tmp_path, "sleep 30\n", timeout_seconds=0.01)
        assert await client.scan_batch(TARGETS, workers=1, cache_dirs=[]) is None


class TestFieldsThatArriveMalformed:
    @pytest.mark.asyncio
    async def test_an_unknown_status_becomes_error_and_not_a_verified_scan(self, tmp_path):
        """O default tem de cair para o lado seguro: um status que este
        lado não reconhece não pode virar uma medição válida."""
        document = json.loads(answer())
        document["results"][0]["status"] = "SOMETHING_NEW"
        client = client_for(tmp_path, emit(json.dumps(document)))

        outcome = await client.scan_batch(TARGETS, workers=1, cache_dirs=[])

        assert outcome is not None
        assert outcome.results[0].status is ScanStatus.ERROR
        assert outcome.results[0].is_verified is False

    @pytest.mark.asyncio
    async def test_an_unknown_error_kind_becomes_unknown(self, tmp_path):
        document = json.loads(answer())
        document["results"][0]["error_kind"] = "NOT_A_KIND"
        client = client_for(tmp_path, emit(json.dumps(document)))

        outcome = await client.scan_batch(TARGETS, workers=1, cache_dirs=[])

        assert outcome is not None
        assert outcome.results[0].error_kind is ScanErrorKind.UNKNOWN

    @pytest.mark.asyncio
    async def test_a_result_that_is_not_an_object_becomes_an_error_result(self, tmp_path):
        client = client_for(tmp_path, emit(answer(results=["nonsense"])))
        outcome = await client.scan_batch(TARGETS, workers=1, cache_dirs=[])

        assert outcome is not None
        assert outcome.results[0].status is ScanStatus.ERROR
        assert outcome.results[0].error_kind is ScanErrorKind.INVALID_OUTPUT

    @pytest.mark.asyncio
    async def test_missing_metrics_are_zero_and_not_a_crash(self, tmp_path):
        client = client_for(tmp_path, emit(answer(metrics="not a dict")))
        outcome = await client.scan_batch(TARGETS, workers=1, cache_dirs=[])

        assert outcome is not None
        assert outcome.scans_performed == 0
        assert outcome.wall_seconds == 0.0

    @pytest.mark.asyncio
    async def test_a_vulnerability_with_an_unknown_severity_is_unknown(self, tmp_path):
        document = json.loads(answer())
        document["results"][0]["vulnerabilities"] = [
            {"cve_id": "CVE-1", "severity": "SPICY", "cvss_score": "not a number"}
        ]
        client = client_for(tmp_path, emit(json.dumps(document)))

        outcome = await client.scan_batch(TARGETS, workers=1, cache_dirs=[])

        assert outcome is not None
        vuln = outcome.results[0].vulnerabilities[0]
        assert vuln.severity is Severity.UNKNOWN
        assert vuln.cvss_score == 0.0

    @pytest.mark.asyncio
    async def test_threat_intelligence_never_crosses_the_boundary_as_a_negative(self, tmp_path):
        """A engine não consulta KEV, EPSS nem Exploit-DB. Um default
        `False` atravessando a fronteira viraria "consultado e negativo",
        que é exatamente a confusão que o Tristate existe para impedir."""
        from dockerls.domain.value_objects.tristate import Tristate

        document = json.loads(answer())
        document["results"][0]["vulnerabilities"] = [{"cve_id": "CVE-1", "severity": "HIGH"}]
        client = client_for(tmp_path, emit(json.dumps(document)))

        outcome = await client.scan_batch(TARGETS, workers=1, cache_dirs=[])

        assert outcome is not None
        vuln = outcome.results[0].vulnerabilities[0]
        assert vuln.kev_status is Tristate.UNKNOWN
        assert vuln.exploitdb_status is Tristate.UNKNOWN
        assert vuln.epss_known is False
