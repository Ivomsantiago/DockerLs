from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from dockerls.application.services.scan_history_store import ScanHistoryStore
from dockerls.application.services.tag_history_store import TagHistoryStore
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


class TestTagDriftDetection:
    """F13: the cache already keys by digest, so a moved tag never serves
    stale evidence -- what was missing was *saying* the tag moved. `base`
    already reports this for Dockerfile-pinned bases; this is the same
    fact for a tag looked up directly with `analyze`."""

    @pytest.mark.asyncio
    async def test_a_tag_that_changed_digest_is_reported(self):
        history = TagHistoryStore(MockCache())
        old_digest = "sha256:" + "a" * 64
        new_digest = "sha256:" + "b" * 64

        first = AnalyzeImageUseCase(
            repository=MockRepo([DockerImage(name="node", tag="22-alpine", digest=old_digest)]),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
            tag_history=history,
        )
        await first.execute("node:22-alpine")

        second = AnalyzeImageUseCase(
            repository=MockRepo([DockerImage(name="node", tag="22-alpine", digest=new_digest)]),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
            tag_history=history,
        )
        result = await second.execute("node:22-alpine")

        assert result.tag_drift_note != ""
        assert "1" in result.tag_drift_note

    @pytest.mark.asyncio
    async def test_the_first_time_a_tag_is_seen_nothing_is_reported(self):
        history = TagHistoryStore(MockCache())
        image = DockerImage(name="node", tag="22-alpine", digest="sha256:" + "a" * 64)
        uc = AnalyzeImageUseCase(MockRepo([image]), MockScanner(), MockEOL(), tag_history=history)

        result = await uc.execute("node:22-alpine")

        assert result.tag_drift_note == ""

    @pytest.mark.asyncio
    async def test_the_same_digest_seen_twice_is_not_a_move(self):
        history = TagHistoryStore(MockCache())
        image = DockerImage(name="node", tag="22-alpine", digest="sha256:" + "a" * 64)

        for _ in range(2):
            uc = AnalyzeImageUseCase(
                MockRepo([image]), MockScanner(), MockEOL(), tag_history=history
            )
            result = await uc.execute("node:22-alpine")

        assert result.tag_drift_note == ""

    @pytest.mark.asyncio
    async def test_a_digest_reference_has_no_tag_to_track(self):
        """`node@sha256:...` asked for a fixed set of bytes, not a tag --
        there is no "move" to observe."""
        history = TagHistoryStore(MockCache())
        uc = AnalyzeImageUseCase(MockRepo(), MockScanner(), MockEOL(), tag_history=history)

        result = await uc.execute(f"node@{'sha256:' + 'a' * 64}")

        assert result.tag_drift_note == ""

    @pytest.mark.asyncio
    async def test_without_a_tag_history_store_nothing_is_reported(self, tags):
        uc = AnalyzeImageUseCase(MockRepo(tags), MockScanner(), MockEOL())
        result = await uc.execute("node:22-alpine")
        assert result.tag_drift_note == ""


class TestVulnTrendDetection:
    """Same idea as tag drift, one level down: not just 'did the bytes
    change' but 'did the count of findings in them change'. Unlike tag
    drift this applies to a digest reference too -- the scanner's own
    database can learn about a new CVE for the exact same, unmoving bytes
    between two runs."""

    @staticmethod
    def _image(digest: str) -> DockerImage:
        return DockerImage(name="node", tag="22-alpine", digest=digest)

    @pytest.mark.asyncio
    async def test_a_changed_vuln_count_is_reported(self):
        history = ScanHistoryStore(MockCache())
        digest = "sha256:" + "a" * 64
        crit_vuln = Vulnerability(cve_id="CVE-1", severity=Severity.CRITICAL, package_name="pkg")

        first = AnalyzeImageUseCase(
            repository=MockRepo([self._image(digest)]),
            scanner=MockScanner(vulns=[]),
            eol_checker=MockEOL(),
            scan_history=history,
        )
        await first.execute("node:22-alpine")

        second = AnalyzeImageUseCase(
            repository=MockRepo([self._image(digest)]),
            scanner=MockScanner(vulns=[crit_vuln]),
            eol_checker=MockEOL(),
            scan_history=history,
        )
        result = await second.execute("node:22-alpine")

        assert "critical +1" in result.vuln_trend_note

    @pytest.mark.asyncio
    async def test_the_first_scan_has_nothing_to_compare_against(self):
        history = ScanHistoryStore(MockCache())
        uc = AnalyzeImageUseCase(
            repository=MockRepo([self._image("sha256:" + "a" * 64)]),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
            scan_history=history,
        )
        result = await uc.execute("node:22-alpine")
        assert result.vuln_trend_note == ""

    @pytest.mark.asyncio
    async def test_unchanged_counts_report_nothing(self):
        history = ScanHistoryStore(MockCache())
        digest = "sha256:" + "a" * 64

        for _ in range(2):
            uc = AnalyzeImageUseCase(
                repository=MockRepo([self._image(digest)]),
                scanner=MockScanner(vulns=[]),
                eol_checker=MockEOL(),
                scan_history=history,
            )
            result = await uc.execute("node:22-alpine")

        assert result.vuln_trend_note == ""

    @pytest.mark.asyncio
    async def test_a_failed_scan_is_never_recorded(self):
        """A scan that did not complete has no counts worth trusting --
        recording it would let a technical failure masquerade as 'zero
        vulnerabilities found'."""
        history = ScanHistoryStore(MockCache())
        uc = AnalyzeImageUseCase(
            repository=MockRepo([self._image("sha256:" + "a" * 64)]),
            scanner=MockScanner(status=ScanStatus.ERROR),
            eol_checker=MockEOL(),
            scan_history=history,
        )
        result = await uc.execute("node:22-alpine")

        assert result.vuln_trend_note == ""
        assert (await history.get("node:22-alpine")).is_empty

    @pytest.mark.asyncio
    async def test_without_a_scan_history_store_nothing_is_reported(self):
        uc = AnalyzeImageUseCase(
            repository=MockRepo([self._image("sha256:" + "a" * 64)]),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node:22-alpine")
        assert result.vuln_trend_note == ""


class _RecordingObserver:
    """Records every `phase()` description, in order, for assertions."""

    def __init__(self):
        self.phases: list[str] = []

    def start(self, total):
        return None

    def scanning(self, image_reference):
        return None

    def finished(self, image_reference, ok):
        return None

    def phase(self, description):
        self.phases.append(description)

    def phase_result(self, title, facts):
        return None


class _ScannerWithAttemptCallback(MockScanner):
    """A scanner whose `refresh_db` reports retry attempts, like Trivy's."""

    def __init__(self, attempts_before_success: int = 1):
        super().__init__()
        self.attempts_before_success = attempts_before_success
        self.refresh_calls = 0

    async def refresh_db(self, on_attempt=None):
        for attempt in range(1, self.attempts_before_success + 1):
            self.refresh_calls += 1
            if on_attempt is not None:
                on_attempt(attempt, self.attempts_before_success)
        return True


class _ScannerWithPlainRefreshDb(MockScanner):
    """A scanner whose `refresh_db` takes no arguments -- Grype's, and every
    test double written before the attempt callback existed."""

    def __init__(self):
        super().__init__()
        self.refresh_calls = 0

    async def refresh_db(self):
        self.refresh_calls += 1
        return True


class TestRefreshDbProgress:
    """`RecommendImagesUseCase` surfaces DB-download retry attempts on the
    observer when the scanner supports it, and still works when it does
    not."""

    @pytest.mark.asyncio
    async def test_attempt_progress_reaches_the_observer(self, tags):
        scanner = _ScannerWithAttemptCallback(attempts_before_success=2)
        observer = _RecordingObserver()
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=scanner,
            eol_checker=MockEOL(),
            observer=observer,
        )
        await uc.execute("node")

        assert scanner.refresh_calls == 2
        assert any("attempt 1/2" in p for p in observer.phases)
        assert any("attempt 2/2" in p for p in observer.phases)

    @pytest.mark.asyncio
    async def test_a_refresh_db_with_no_on_attempt_parameter_still_runs(self, tags):
        """TypeError from an incompatible signature falls back to the plain
        call rather than being mistaken for a scanner failure."""
        scanner = _ScannerWithPlainRefreshDb()
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=scanner,
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node")

        assert scanner.refresh_calls == 1
        assert result.baseline_met is True


class _SlowRefreshScanner(MockScanner):
    """A scanner whose `refresh_db` takes measurable time, so it can be
    observed overlapping (or not) with the tag search."""

    def __init__(self, delay: float, log: list[str]):
        super().__init__()
        self._delay = delay
        self._log = log

    async def refresh_db(self, on_attempt=None):
        self._log.append("db-start")
        await asyncio.sleep(self._delay)
        self._log.append("db-end")
        return True


class _SlowRepo(ImageRepositoryInterface):
    """A repository whose `search_tags` takes measurable time."""

    def __init__(self, tags, delay: float, log: list[str]):
        self._tags = tags
        self._delay = delay
        self._log = log

    async def search_tags(self, image_name, limit=100):
        self._log.append("tags-start")
        await asyncio.sleep(self._delay)
        self._log.append("tags-end")
        return self._tags[:limit]

    async def get_image_metadata(self, image_name, tag):
        return None


class TestDbRefreshOverlapsTagSearch:
    """The vulnerability-database download and the tag search touch
    nothing in common, so they run concurrently instead of one blocking
    the other -- see `_execute` in `RecommendImagesUseCase`."""

    @pytest.mark.asyncio
    async def test_both_operations_overlap(self, tags):
        log: list[str] = []
        uc = RecommendImagesUseCase(
            repository=_SlowRepo(tags, delay=0.05, log=log),
            scanner=_SlowRefreshScanner(delay=0.05, log=log),
            eol_checker=MockEOL(),
        )
        await uc.execute("node")

        # Sequential would read db-start, db-end, tags-start, tags-end (or
        # the reverse). Overlapping, the second operation starts before
        # the first ends.
        assert log.index("tags-start") < log.index("db-end")


class TestCompareImages:
    @pytest.mark.asyncio
    async def test_compare(self, tags):
        analyze_uc = AnalyzeImageUseCase(MockRepo(tags), MockScanner(), MockEOL())
        uc = CompareImagesUseCase(analyze_uc)
        result = await uc.execute(["node:22-alpine", "node:20-alpine"])
        assert len(result.images) == 2
        assert result.winner != ""
