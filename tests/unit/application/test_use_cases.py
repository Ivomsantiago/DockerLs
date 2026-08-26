from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface


class MockRepo(ImageRepositoryInterface):
    def __init__(self, tags=None):
        self._tags = tags or []

    async def search_tags(self, image_name, limit=100):
        return self._tags[:limit]

    async def get_image_metadata(self, image_name, tag):
        for t in self._tags:
            if t.tag == tag:
                return t
        return None


class MockScanner(ScannerInterface):
    def __init__(self, vulns=None, status=ScanStatus.OK):
        self._vulns = vulns or []
        self._status = status
        self.calls: list[str] = []

    async def scan(self, image_reference):
        self.calls.append(image_reference)
        return ScanResult(
            image_reference=image_reference,
            vulnerabilities=self._vulns,
            status=self._status,
            # Real scanners always stamp a completed scan; the verification
            # gate treats a missing timestamp as "no scan actually ran".
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            error_message="boom" if self._status != ScanStatus.OK else "",
        )

    async def is_available(self):
        return True


class MockEOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


class MockCache(CacheStoreInterface):
    def __init__(self):
        self._store: dict = {}

    async def get(self, key):
        return self._store.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self._store[key] = value

    async def delete(self, key):
        self._store.pop(key, None)

    async def clear(self):
        self._store.clear()


@pytest.fixture
def tags():
    return [
        DockerImage(name="node", tag="22-alpine", is_official=True),
        DockerImage(name="node", tag="22-bookworm-slim", is_official=True),
        DockerImage(name="node", tag="20-alpine", is_official=True),
    ]


class TestSearchImages:
    @pytest.mark.asyncio
    async def test_search(self, tags):
        uc = SearchImagesUseCase(MockRepo(tags))
        result = await uc.execute("node")
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_search_empty(self):
        uc = SearchImagesUseCase(MockRepo())
        result = await uc.execute("nonexistent")
        assert len(result) == 0


class TestRecommendImages:
    @pytest.mark.asyncio
    async def test_baseline_met(self, tags):
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
            cache=MockCache(),
        )
        result = await uc.execute("node")
        assert result.baseline_met is True
        assert len(result.recommendations) > 0

    @pytest.mark.asyncio
    async def test_fallback(self, tags):
        vulns = [Vulnerability(cve_id="H1", severity=Severity.HIGH, fixed_version="1.0")]
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(vulns),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node")
        assert result.baseline_met is False
        assert len(result.alternatives) > 0

    @pytest.mark.asyncio
    async def test_no_tags(self):
        uc = RecommendImagesUseCase(
            repository=MockRepo(),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("nothing")
        assert result.baseline_met is False
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_error_scans_never_recommended(self, tags):
        scanner = MockScanner(status=ScanStatus.ERROR)
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=scanner,
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node")
        assert result.baseline_met is False
        assert result.recommendations == []
        assert result.alternatives == []
        assert len(result.errors) == len(tags)

    @pytest.mark.asyncio
    async def test_ignore_file_excludes_cve_from_scoring(self, tags, tmp_path):
        ignore_file = tmp_path / ".dockerls-ignore.yaml"
        ignore_file.write_text("ignores:\n  - cve: CVE-IGNORED\n    justification: test\n")
        vulns = [Vulnerability(cve_id="CVE-IGNORED", severity=Severity.CRITICAL)]
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(vulns),
            eol_checker=MockEOL(),
            ignore_path=ignore_file,
        )
        result = await uc.execute("node")
        assert result.baseline_met is True

    @pytest.mark.asyncio
    async def test_threat_intel_enrichment_applied(self, tags):
        from unittest.mock import AsyncMock

        from dockerls.integrations.threat_intel.client import ThreatIntelClient

        vulns = [Vulnerability(cve_id="CVE-2024-0001", severity=Severity.HIGH, fixed_version="1.0")]
        threat_intel = ThreatIntelClient()
        threat_intel.known_exploited = AsyncMock(return_value={"CVE-2024-0001"})
        threat_intel.epss_scores = AsyncMock(return_value={"CVE-2024-0001": 0.95})

        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(vulns),
            eol_checker=MockEOL(),
            threat_intel=threat_intel,
        )
        result = await uc.execute("node")
        best = (result.recommendations or result.alternatives)[0]
        assert best.scan.vulnerabilities[0].exploit_known is True
        assert best.scan.vulnerabilities[0].epss_score == 0.95

    @pytest.mark.asyncio
    async def test_dedup_scans_by_digest(self):
        shared_tags = [
            DockerImage(name="node", tag="22-alpine", digest="sha256:abc", is_official=True),
            DockerImage(name="node", tag="22", digest="sha256:abc", is_official=True),
            DockerImage(name="node", tag="20-alpine", digest="sha256:xyz", is_official=True),
        ]
        scanner = MockScanner()
        uc = RecommendImagesUseCase(
            repository=MockRepo(shared_tags),
            scanner=scanner,
            eol_checker=MockEOL(),
        )
        await uc.execute("node")
        assert len(scanner.calls) == 2


class TestAnalyzeImage:
    @pytest.mark.asyncio
    async def test_analyze(self, tags):
        uc = AnalyzeImageUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node:22-alpine")
        assert result.security_score > 0
        assert result.tier in ("A", "B", "C", "D", "E", "F")

    @pytest.mark.asyncio
    async def test_parse_reference(self):
        uc = AnalyzeImageUseCase(MockRepo(), MockScanner(), MockEOL())
        assert uc._parse_reference("node:22-alpine") == ("node", "22-alpine")
        assert uc._parse_reference("python") == ("python", "latest")

    @pytest.mark.asyncio
    async def test_a_registry_port_is_not_read_as_a_tag(self):
        """`rsplit(":", 1)` lia `registry.internal:5000/app` como o produto
        "registry.internal" na versão "5000", e a consulta de EOL/LTS
        recebia isso. O alvo do scan sobrevivia por acidente."""
        uc = AnalyzeImageUseCase(MockRepo(), MockScanner(), MockEOL())
        assert uc._parse_reference("registry.internal:5000/app") == (
            "registry.internal:5000/app",
            "latest",
        )
        assert uc._parse_reference("localhost:5000/api:2.1") == ("localhost:5000/api", "2.1")

    @pytest.mark.asyncio
    async def test_a_digest_reference_is_scanned_as_asked(self):
        """Reconstruir `name:tag` a partir de `node@sha256:...` mandaria o
        scanner medir `node:latest` -- outra imagem, sob o nome desta."""
        digest = "sha256:" + "a" * 64
        scanner = MockScanner()
        uc = AnalyzeImageUseCase(MockRepo(), scanner, MockEOL())

        await uc.execute(f"node@{digest}")

        assert scanner.calls == [f"node@{digest}"]

    @pytest.mark.asyncio
    async def test_a_failed_scan_never_raises_the_raw_securityscore_error(self, tags):
        """`SecurityScore` raises on anything but an OK/PARTIAL scan; that
        used to bubble straight out of `execute` and land on the CLI as
        'Scan failed: {raw error_message}', bypassing the classified
        error_kind messaging entirely. A failed scan must instead come back
        as an ImageAnalysis the caller can inspect via `scan.is_verified`."""
        uc = AnalyzeImageUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(status=ScanStatus.ERROR),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node:does-not-exist")
        assert result.scan.is_verified is False
        assert result.security_score == 0.0
        assert result.production_ready is False


class TestCompareImages:
    @pytest.mark.asyncio
    async def test_compare(self, tags):
        analyze_uc = AnalyzeImageUseCase(MockRepo(tags), MockScanner(), MockEOL())
        uc = CompareImagesUseCase(analyze_uc)
        result = await uc.execute(["node:22-alpine", "node:20-alpine"])
        assert len(result.images) == 2
        assert result.winner != ""
