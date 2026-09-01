"""Guard: a política de rede não muda de lado ao entrar no caminho em lote.

A engine Go é um pool de goroutines em volta do Trivy -- e mais nada. O
`HostGuard` e o `sanitize_image_name` continuam do lado Python, aplicados
*antes* de montar a requisição, com o mesmo código do caminho individual.

Isto importa mais do que parece: `trivy image X` abre o próprio socket, e
foi para cobrir esse buraco que `scan_target.py` existe. Se o lote
contornasse o guard, uma referência como `169.254.169.254/latest:v1`
apontaria a conexão do scanner para o endpoint de metadados da nuvem -- por
uma porta nova, aberta em nome de desempenho.
"""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

import pytest

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanStatus
from dockerls.domain.value_objects.network_policy import NetworkPolicy
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.integrations.engine.locator import PROTOCOL_VERSION
from dockerls.integrations.trivy.scanner import TrivyScanner

if TYPE_CHECKING:
    from pathlib import Path


def install_fake_engine(tmp_path: Path, monkeypatch, *, record_to: Path | None = None) -> Path:
    """Uma engine falsa que devolve OK para cada alvo que receber, e que
    grava a requisição recebida -- é ela que prova o que atravessou.

    A requisição é sempre gravada, mesmo quando o teste não vai lê-la: é
    dela que o responder tira os alvos, e um `/dev/null` aqui faria a
    engine falsa responder zero resultados para qualquer lote.
    """
    record_to = record_to or (tmp_path / "request.json")
    script = tmp_path / "fake-engine"
    recorder = f'cat > "{record_to}"\n'
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-version" ]; then\n'
        f"  echo 'dockerls-engine protocol {PROTOCOL_VERSION}'\n"
        "  exit 0\n"
        "fi\n"
        f"{recorder}"
        f'python3 "{tmp_path / "respond.py"}" "{record_to}"\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    # O responder lê a requisição gravada e devolve um resultado por alvo,
    # o que é o contrato: alinhamento por posição.
    (tmp_path / "respond.py").write_text(
        "import json, sys\n"
        "try:\n"
        "    request = json.load(open(sys.argv[1]))\n"
        "except Exception:\n"
        "    request = {'targets': []}\n"
        "results = [{\n"
        "    'image_reference': t['reference'], 'scanner': 'trivy', 'vulnerabilities': [],\n"
        "    'scan_timestamp': '2026-01-01T00:00:00+00:00', 'status': 'OK',\n"
        "    'error_message': '', 'error_kind': 'NONE', 'os_family': 'alpine',\n"
        "    'os_version': '3.21', 'raw_path': '',\n"
        "} for t in request.get('targets', [])]\n"
        f"print(json.dumps({{'version': {PROTOCOL_VERSION}, 'results': results,\n"
        "    'metrics': {'scans_performed': len(results), 'duplicates_collapsed': 0,\n"
        "                'wall_seconds': 0.1}}))\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(script))
    monkeypatch.setattr(
        "dockerls.integrations.engine.batch.resolve_executable", lambda name: f"/usr/bin/{name}"
    )
    return script


class TestThePolicyIsEnforcedBeforeTheBatchIsBuilt:
    @pytest.mark.asyncio
    async def test_a_refused_reference_never_reaches_the_engine(self, tmp_path, monkeypatch):
        received = tmp_path / "request.json"
        install_fake_engine(tmp_path, monkeypatch, record_to=received)

        # Loopback é o caso SSRF, e é recusado por padrão.
        guard = HostGuard(NetworkPolicy(allow_loopback=False, allow_link_local=False))
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2, guard=guard)

        outcome = await scanner.batch.scan_batch(
            [("node:22-alpine", "sha256:aaa"), ("127.0.0.1:5000/evil:1", "sha256:bbb")]
        )

        assert outcome is not None
        request = json.loads(received.read_text(encoding="utf-8"))
        references = [t["reference"] for t in request["targets"]]
        assert references == ["node:22-alpine"]

    @pytest.mark.asyncio
    async def test_a_refused_reference_comes_back_as_blocked_by_policy(self, tmp_path, monkeypatch):
        """Nunca como uma lista de achados vazia: uma imagem que ninguém
        teve permissão de medir não foi medida."""
        install_fake_engine(tmp_path, monkeypatch)
        guard = HostGuard(NetworkPolicy(allow_loopback=False))
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2, guard=guard)

        outcome = await scanner.batch.scan_batch([("127.0.0.1:5000/evil:1", "sha256:bbb")])

        assert outcome is not None
        result = outcome.results[0]
        assert result.status is ScanStatus.ERROR
        assert result.error_kind is ScanErrorKind.BLOCKED_BY_POLICY
        assert result.is_verified is False

    @pytest.mark.asyncio
    async def test_the_results_keep_the_order_of_the_targets_asked_for(self, tmp_path, monkeypatch):
        """Alvos recusados saem da requisição, então o alinhamento por
        posição tem de ser refeito na volta -- e um erro aqui atribuiria a
        medição de uma imagem a outra."""
        install_fake_engine(tmp_path, monkeypatch)
        guard = HostGuard(NetworkPolicy(allow_loopback=False))
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2, guard=guard)

        targets = [
            ("node:22", "sha256:a"),
            ("127.0.0.1:5000/evil:1", "sha256:b"),
            ("node:20", "sha256:c"),
            ("127.0.0.1:5000/evil:2", "sha256:d"),
            ("alpine:3.21", "sha256:e"),
        ]
        outcome = await scanner.batch.scan_batch(targets)

        assert outcome is not None
        assert [r.image_reference for r in outcome.results] == [t[0] for t in targets]
        assert [r.error_kind is ScanErrorKind.BLOCKED_BY_POLICY for r in outcome.results] == [
            False,
            True,
            False,
            True,
            False,
        ]


class TestAnInvalidReferenceDoesNotAbortTheWholeBatch:
    """`sanitize_image_name` raises `ValueError` on a malformed reference.
    Unhandled inside the batch loop, that used to abort every other, valid
    target queued in the same call -- one bad tag failing the whole run."""

    @pytest.mark.asyncio
    async def test_an_invalid_reference_never_reaches_the_engine(self, tmp_path, monkeypatch):
        received = tmp_path / "request.json"
        install_fake_engine(tmp_path, monkeypatch, record_to=received)
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2)

        outcome = await scanner.batch.scan_batch(
            [("node:22-alpine", "sha256:aaa"), ("--offline-scan", "sha256:bbb")]
        )

        assert outcome is not None
        request = json.loads(received.read_text(encoding="utf-8"))
        references = [t["reference"] for t in request["targets"]]
        assert references == ["node:22-alpine"]

    @pytest.mark.asyncio
    async def test_the_other_valid_targets_still_get_measured(self, tmp_path, monkeypatch):
        install_fake_engine(tmp_path, monkeypatch)
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2)

        outcome = await scanner.batch.scan_batch(
            [
                ("node:22", "sha256:a"),
                ("--offline-scan", "sha256:b"),
                ("alpine:3.21", "sha256:c"),
            ]
        )

        assert outcome is not None
        assert [r.image_reference for r in outcome.results] == [
            "node:22",
            "--offline-scan",
            "alpine:3.21",
        ]
        assert [r.status is ScanStatus.OK for r in outcome.results] == [True, False, True]

    @pytest.mark.asyncio
    async def test_the_invalid_target_comes_back_as_an_error_not_an_exception(
        self, tmp_path, monkeypatch
    ):
        install_fake_engine(tmp_path, monkeypatch)
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2)

        outcome = await scanner.batch.scan_batch([("--offline-scan", "sha256:bbb")])

        assert outcome is not None
        result = outcome.results[0]
        assert result.status is ScanStatus.ERROR
        assert result.is_verified is False


class TestFallingBackToThePythonPipeline:
    @pytest.mark.asyncio
    async def test_no_engine_means_no_batch(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(tmp_path / "absent"))
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2)
        assert await scanner.batch.scan_batch([("node:22", "sha256:a")]) is None

    @pytest.mark.asyncio
    async def test_no_trivy_means_no_batch(self, tmp_path, monkeypatch):
        """Sem Trivy não há o que a engine dirija, e o caminho Python dará
        a mesma resposta -- SCANNER_MISSING -- por si."""
        from dockerls.utils.executables import ExecutableNotFoundError

        install_fake_engine(tmp_path, monkeypatch)

        def missing(name: str) -> str:
            raise ExecutableNotFoundError(name)

        monkeypatch.setattr("dockerls.integrations.engine.batch.resolve_executable", missing)
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2)
        assert await scanner.batch.scan_batch([("node:22", "sha256:a")]) is None

    @pytest.mark.asyncio
    async def test_the_engine_is_located_once_per_process(self, tmp_path, monkeypatch):
        """`probe()` custa milissegundos e `find_engine()` toca o disco;
        pagar isso por lote seria repetir a descoberta para uma resposta
        que não muda dentro de um run."""
        install_fake_engine(tmp_path, monkeypatch)
        calls = []
        real_probe = __import__("dockerls.integrations.engine.locator", fromlist=["probe"]).probe

        def counting_probe(path: str) -> bool:
            calls.append(path)
            return real_probe(path)

        monkeypatch.setattr("dockerls.integrations.engine.batch.probe", counting_probe)
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2)

        await scanner.batch.scan_batch([("node:22", "sha256:a")])
        await scanner.batch.scan_batch([("node:20", "sha256:b")])

        assert len(calls) == 1


class TestEvidence:
    @pytest.mark.asyncio
    async def test_no_raw_dir_is_requested_when_evidence_is_off(self, tmp_path, monkeypatch):
        """Sem ninguém para ler e arquivar, gravar o documento **não
        redigido** em disco deixaria para trás exatamente o que a redação
        existe para não deixar."""
        received = tmp_path / "request.json"
        install_fake_engine(tmp_path, monkeypatch, record_to=received)
        scanner = TrivyScanner(cache_dir=tmp_path / "cache", workers=2, evidence=None)

        await scanner.batch.scan_batch([("node:22", "sha256:a")])

        assert json.loads(received.read_text(encoding="utf-8"))["raw_dir"] == ""

    @pytest.mark.asyncio
    async def test_a_raw_dir_is_requested_when_evidence_is_on(self, tmp_path, monkeypatch):
        from dockerls.infrastructure.evidence import EvidenceStore

        received = tmp_path / "request.json"
        install_fake_engine(tmp_path, monkeypatch, record_to=received)
        scanner = TrivyScanner(
            cache_dir=tmp_path / "cache",
            workers=2,
            evidence=EvidenceStore(tmp_path / "evidence"),
        )

        await scanner.batch.scan_batch([("node:22", "sha256:a")])

        assert json.loads(received.read_text(encoding="utf-8"))["raw_dir"] != ""
