"""O pipeline inteiro contra a engine Go de verdade.

Os testes unitários provam as peças; este prova a única coisa que importa
no fim: **o caminho em lote e o caminho Python chegam ao mesmo resultado**.
Uma engine que fosse mais rápida e pontuasse diferente não seria uma
otimização, seria um segundo produto.

O Trivy é substituído por um script que emite um relatório real (não há
scanner nem rede nesta máquina), mas tudo o mais é o de produção: o binário
Go compilado, o protocolo JSON, o `TrivyScanner`, o `RecommendImagesUseCase`.
"""

from __future__ import annotations

import shutil
import stat
import subprocess  # noqa: S404 -- argv fixo, sem shell; compila o binário do próprio repo
import sys
from pathlib import Path

import pytest

from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.integrations.trivy.scanner import TrivyScanner

REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINE_BINARY = REPO_ROOT / "engine" / "bin" / "dockerls-engine"

#: Um relatório do Trivy com uma severidade de cada, para que o score tenha
#: o que medir em vez de sair 100 nos dois caminhos por vacuidade.
TRIVY_REPORT = """{
  "Metadata": {"OS": {"Family": "alpine", "Name": "3.21.0"}},
  "Results": [{
    "Target": "img (alpine 3.21.0)",
    "Class": "os-pkgs",
    "Type": "alpine",
    "Vulnerabilities": [
      {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH", "SeveritySource": "nvd",
       "PkgName": "openssl", "InstalledVersion": "3.1.0", "FixedVersion": "3.1.4",
       "Title": "openssl issue", "CVSS": {"nvd": {"V3Score": 7.5}}},
      {"VulnerabilityID": "CVE-2024-0002", "Severity": "MEDIUM", "SeveritySource": "nvd",
       "PkgName": "busybox", "InstalledVersion": "1.36", "FixedVersion": "",
       "Title": "busybox issue", "CVSS": {"nvd": {"V3Score": 5.3}}}
    ]
  }]
}"""


pytestmark = pytest.mark.skipif(
    not ENGINE_BINARY.is_file(),
    reason="the Go engine has not been built (run `make engine`)",
)


class FakeRepo(ImageRepositoryInterface):
    def __init__(self, tags: list[DockerImage]) -> None:
        self._tags = tags

    async def search_tags(self, image_name, limit=100):
        return self._tags[:limit]

    async def get_image_metadata(self, image_name, tag):
        return next((t for t in self._tags if t.tag == tag), None)


class FakeEOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


@pytest.fixture
def tags() -> list[DockerImage]:
    return [
        # Os dois primeiros compartilham o digest: é o caso que o dedup
        # existe para colapsar, e ele tem de valer nos dois caminhos.
        DockerImage(name="node", tag="22-alpine", digest="sha256:aaa", is_official=True),
        DockerImage(name="node", tag="22", digest="sha256:aaa", is_official=True),
        DockerImage(name="node", tag="20-alpine", digest="sha256:bbb", is_official=True),
    ]


@pytest.fixture
def fake_trivy(tmp_path: Path, monkeypatch) -> Path:
    """Um Trivy que responde o mesmo relatório para qualquer imagem."""
    path = tmp_path / "trivy"
    path.write_text(f"#!/bin/sh\ncat <<'REPORT'\n{TRIVY_REPORT}\nREPORT\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(
        "dockerls.integrations.trivy.scanner.resolve_executable",
        lambda name: str(path) if name == "trivy" else f"/usr/bin/{name}",
    )
    return path


def _use_case(tags: list[DockerImage], tmp_path: Path, suffix: str) -> RecommendImagesUseCase:
    return RecommendImagesUseCase(
        repository=FakeRepo(tags),
        scanner=TrivyScanner(timeout=30, workers=2, cache_dir=tmp_path / f"cache-{suffix}"),
        eol_checker=FakeEOL(),
    )


class TestBothPathsAgree:
    @pytest.mark.asyncio
    async def test_the_engine_and_the_python_pipeline_produce_the_same_verdict(
        self, tags, tmp_path, fake_trivy, monkeypatch
    ):
        """A afirmação central: mais rápido, e a mesma resposta."""
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(ENGINE_BINARY))
        with_engine = await _use_case(tags, tmp_path, "go").execute("node")

        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(tmp_path / "absent"))
        without_engine = await _use_case(tags, tmp_path, "py").execute("node")

        assert with_engine.baseline_met == without_engine.baseline_met

        engine_items = with_engine.recommendations or with_engine.alternatives
        python_items = without_engine.recommendations or without_engine.alternatives
        assert len(engine_items) == len(python_items)

        for measured, expected in zip(engine_items, python_items, strict=True):
            assert measured.image.full_reference == expected.image.full_reference
            assert measured.security_score == expected.security_score
            assert measured.tier == expected.tier
            assert measured.remediation_score == expected.remediation_score
            assert measured.scan.high_count == expected.scan.high_count
            assert measured.scan.medium_count == expected.scan.medium_count
            assert measured.scan.fixable_high_count == expected.scan.fixable_high_count
            assert measured.scan.os_family == expected.scan.os_family


class TestWhatTheBatchChanges:
    @pytest.mark.asyncio
    async def test_tags_sharing_a_digest_are_still_scanned_once(
        self, tags, tmp_path, fake_trivy, monkeypatch
    ):
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(ENGINE_BINARY))
        use_case = _use_case(tags, tmp_path, "dedup")

        await use_case.execute("node")

        # Três tags, dois digests: o dedup do caminho em lote é o mesmo
        # dedup, feito dentro da engine em vez de em asyncio.Lock.
        assert use_case._metrics.scans_performed == 2

    @pytest.mark.asyncio
    async def test_every_measured_image_is_verified(self, tags, tmp_path, fake_trivy, monkeypatch):
        """Um scan que atravessou a fronteira sem carimbo de tempo seria
        pontuado como F sem nunca ter falhado."""
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(ENGINE_BINARY))
        result = await _use_case(tags, tmp_path, "verified").execute("node")

        items = result.recommendations or result.alternatives
        assert items
        for item in items:
            assert item.scan.is_verified is True
            assert item.scan.scan_timestamp

    @pytest.mark.asyncio
    async def test_a_scanner_that_fails_is_unverified_and_never_recommended(
        self, tags, tmp_path, monkeypatch
    ):
        broken = tmp_path / "trivy"
        broken.write_text(
            "#!/bin/sh\necho 'UNAUTHORIZED: authentication required' >&2\nexit 1\n",
            encoding="utf-8",
        )
        broken.chmod(broken.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setattr(
            "dockerls.integrations.trivy.scanner.resolve_executable", lambda name: str(broken)
        )
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(ENGINE_BINARY))

        result = await _use_case(tags, tmp_path, "broken").execute("node")

        assert result.baseline_met is False
        assert result.recommendations == []
        assert result.alternatives == []
        assert result.errors


class TestTheBinaryItselfIsCurrent:
    def test_the_committed_source_still_builds_and_speaks_this_protocol(self, tmp_path):
        """Um binário compilado de um commit antigo passaria em tudo acima
        e mentiria sobre o código que está no repositório."""
        from dockerls.integrations.engine.locator import PROTOCOL_VERSION

        go = shutil.which("go")
        if go is None:
            pytest.skip("no Go toolchain on this machine")

        built = tmp_path / "engine"
        compile_result = subprocess.run(  # noqa: S603 -- argv fixo, caminho absoluto, sem shell
            [go, "build", "-o", str(built), "./cmd/dockerls-engine"],
            cwd=REPO_ROOT / "engine",
            capture_output=True,
            text=True,
            check=False,
        )
        if compile_result.returncode != 0:
            pytest.skip(f"no usable Go toolchain here: {compile_result.stderr[:200]}")

        version = subprocess.run(  # noqa: S603 -- argv fixo, sem shell
            [str(built), "-version"], capture_output=True, text=True, check=True
        )
        assert f"protocol {PROTOCOL_VERSION}" in version.stdout


def test_the_test_module_itself_would_notice_a_missing_binary():
    """O `skipif` acima é silencioso por natureza. Se o binário sumir, esta
    suíte inteira passa a não provar nada -- e isso tem de ficar visível."""
    if not ENGINE_BINARY.is_file():
        print(  # noqa: T201 -- é a mensagem, e o ponto é ela aparecer
            f"\nNOTE: {ENGINE_BINARY} is absent; the Go engine tests did not run.",
            file=sys.stderr,
        )


GRYPE_REPORT = """{
  "distro": {"name": "alpine", "version": "3.21.0"},
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-0001", "severity": "High",
        "description": "openssl issue",
        "fix": {"versions": ["3.1.4"]},
        "cvss": [{"source": "nvd", "metrics": {"baseScore": 7.5}}]
      },
      "artifact": {"name": "openssl", "version": "3.1.0", "type": "apk",
                   "locations": [{"path": "/lib/apk/db/installed"}]}
    }
  ]
}"""


class TestGrypeGoesThroughTheSameEngine:
    """A engine dirige os dois scanners, e o Python não precisa saber qual.

    O que difere -- argv, forma do JSON, cache dir versus variável de
    ambiente -- fica inteiramente do lado Go. Estes testes provam que a
    diferença termina ali: os dois caminhos entregam o mesmo `ScanResult`.
    """

    @pytest.fixture
    def fake_grype(self, tmp_path: Path, monkeypatch) -> Path:
        path = tmp_path / "grype"
        path.write_text(f"#!/bin/sh\ncat <<'REPORT'\n{GRYPE_REPORT}\nREPORT\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setattr(
            "dockerls.integrations.engine.batch.resolve_executable",
            lambda name: str(path) if name == "grype" else f"/usr/bin/{name}",
        )
        return path

    @pytest.mark.asyncio
    async def test_a_grype_batch_produces_domain_results(self, tmp_path, fake_grype, monkeypatch):
        from dockerls.integrations.grype.scanner import GrypeScanner

        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(ENGINE_BINARY))
        scanner = GrypeScanner(timeout=30, workers=4)

        outcome = await scanner.batch.scan_batch(
            [("node:22-alpine", "sha256:aaa"), ("node:20-alpine", "sha256:bbb")]
        )

        assert outcome is not None
        assert outcome.scans_performed == 2
        for result in outcome.results:
            assert result.scanner == "grype"
            assert result.is_verified is True
            assert result.os_family == "alpine"
            assert result.high_count == 1
            assert result.vulnerabilities[0].cvss_score == 7.5
            assert result.vulnerabilities[0].fixed_version == "3.1.4"

    @pytest.mark.asyncio
    async def test_the_batch_and_the_single_scan_agree(self, tmp_path, fake_grype, monkeypatch):
        """Se os dois caminhos discordassem, a cross-validação passaria a
        depender de qual deles rodou -- e ela existe justamente para não
        depender de quem mediu."""
        from dockerls.integrations.grype.scanner import GrypeScanner

        monkeypatch.setattr(
            "dockerls.integrations.grype.scanner.resolve_executable", lambda name: str(fake_grype)
        )
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(ENGINE_BINARY))
        scanner = GrypeScanner(timeout=30, workers=2)

        batched = await scanner.batch.scan_batch([("node:22-alpine", "")])
        single = await scanner.scan("node:22-alpine")

        assert batched is not None
        measured = batched.results[0]
        assert measured.scanner == single.scanner
        assert measured.os_family == single.os_family
        assert measured.high_count == single.high_count
        assert [v.cve_id for v in measured.vulnerabilities] == [
            v.cve_id for v in single.vulnerabilities
        ]
        assert measured.vulnerabilities[0].cvss_score == single.vulnerabilities[0].cvss_score
        assert measured.vulnerabilities[0].target == single.vulnerabilities[0].target

    @pytest.mark.asyncio
    async def test_the_whole_environment_never_crosses_the_boundary(self, tmp_path, monkeypatch):
        """O ambiente do processo carrega DOCKERHUB_TOKEN e companhia.
        Mandá-lo inteiro pela fronteira escreveria segredo dentro de um
        documento JSON -- só o par do Grype atravessa."""
        from dockerls.integrations.grype.scanner import GrypeScanner

        monkeypatch.setenv("DOCKERHUB_TOKEN", "nao-pode-atravessar")
        scanner = GrypeScanner(timeout=30, workers=1)
        scanner._skip_db_update = True

        env = scanner._batch_env()

        assert set(env) == {"GRYPE_DB_AUTO_UPDATE", "GRYPE_CHECK_FOR_APP_UPDATE"}
        assert "nao-pode-atravessar" not in str(env)
