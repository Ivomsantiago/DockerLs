"""Regression tests for the core reliability invariant:

    an image is never recommended without proof of a successful scan.

Each test drives the real `RecommendImagesUseCase` (not a stub) through a
failure mode that previously could still yield a scored, tiered row in the
"Recommended Images" table.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.use_cases.recommend_images import (
    UnverifiedRecommendationError,
    _assert_verified,
)
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.domain.value_objects.security_score import SecurityScore

TAGS = [
    DockerImage(name="node", tag="26.7-slim", is_official=True),
    DockerImage(name="node", tag="22-alpine", is_official=True),
]


class _Repo(ImageRepositoryInterface):
    def __init__(self, tags=TAGS, existing_tags=None):
        self._tags = tags
        # None => no tag_exists behaviour configured, everything "exists".
        self._existing = existing_tags

    async def search_tags(self, image_name, limit=100):
        return self._tags[:limit]

    async def get_image_metadata(self, image_name, tag):
        return None

    async def tag_exists(self, image_name, tag):
        if self._existing is None:
            return True
        return tag in self._existing


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


class _ExitCodeScanner(ScannerInterface):
    """Simulates a scanner binary exiting non-zero (e.g. Trivy's cache lock
    timeout), which is what `TrivyScanner.scan` turns into ScanStatus.ERROR."""

    def __init__(self, returncode: int = 1):
        self._returncode = returncode

    async def scan(self, image_reference):
        return ScanResult(
            image_reference=image_reference,
            scanner="trivy",
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            status=ScanStatus.ERROR,
            error_message=(
                f"trivy exited with code {self._returncode}: "
                "cache may be in use by another process: timeout"
            ),
        )

    async def is_available(self):
        return True


class _PlaceholderScanner(ScannerInterface):
    """Returns a default-constructed ScanResult: status OK, but no
    timestamp and no findings -- the shape a "no data" fallback would have."""

    async def scan(self, image_reference):
        return ScanResult(image_reference=image_reference)

    async def is_available(self):
        return True


class _CleanScanner(ScannerInterface):
    async def scan(self, image_reference):
        return ScanResult(
            image_reference=image_reference,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
        )

    async def is_available(self):
        return True


def _use_case(scanner, repository=None, **kwargs):
    from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase

    return RecommendImagesUseCase(
        repository=repository or _Repo(),
        scanner=scanner,
        eol_checker=_EOL(),
        **kwargs,
    )


class TestScannerExitCodeNeverRecommends:
    @pytest.mark.asyncio
    async def test_trivy_exit_code_1_yields_no_recommendation(self):
        result = await _use_case(_ExitCodeScanner(1)).execute("node")

        assert result.recommendations == []
        assert result.alternatives == []
        assert result.baseline_met is False
        assert result.total_tags_analyzed == 0

    @pytest.mark.asyncio
    async def test_failed_images_are_listed_as_unverified(self):
        result = await _use_case(_ExitCodeScanner(1)).execute("node")

        assert result.unverified_count == len(TAGS)
        refs = {u.image_reference for u in result.unverified}
        assert refs == {t.full_reference for t in TAGS}
        for item in result.unverified:
            assert item.status == ScanStatus.ERROR.value
            assert "cache may be in use" in item.reason

    @pytest.mark.asyncio
    async def test_unverified_images_carry_no_score_or_tier(self):
        result = await _use_case(_ExitCodeScanner(1)).execute("node")

        # UnverifiedImage has no score/tier fields at all -- an unscannable
        # image cannot be assigned a number by construction.
        payload = result.unverified[0].model_dump()
        assert "security_score" not in payload
        assert "tier" not in payload

    @pytest.mark.asyncio
    async def test_mixed_success_and_failure_only_recommends_the_success(self):
        class _Flaky(ScannerInterface):
            async def scan(self, image_reference):
                if "26.7-slim" in image_reference:
                    return ScanResult(
                        image_reference=image_reference,
                        scan_timestamp=datetime.now(tz=UTC).isoformat(),
                        status=ScanStatus.ERROR,
                        error_message="exit status 1",
                    )
                return ScanResult(
                    image_reference=image_reference,
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

            async def is_available(self):
                return True

        result = await _use_case(_Flaky()).execute("node")

        recommended = {a.image.full_reference for a in result.recommendations}
        assert recommended == {"node:22-alpine"}
        assert [u.image_reference for u in result.unverified] == ["node:26.7-slim"]


class TestPlaceholderScansRejected:
    @pytest.mark.asyncio
    async def test_untimestamped_scan_is_not_verified(self):
        result = await _use_case(_PlaceholderScanner()).execute("node")

        assert result.recommendations == []
        assert result.unverified_count == len(TAGS)

    def test_timeout_status_is_not_verified(self):
        scan = ScanResult(
            image_reference="node:22",
            status=ScanStatus.TIMEOUT,
            scan_timestamp="2026-01-01T00:00:00Z",
        )
        assert scan.is_verified is False

    def test_partial_status_is_not_verified(self):
        """PARTIAL means some targets could not be inspected, so its counts
        are a lower bound -- not proof the image is clean."""
        scan = ScanResult(
            image_reference="node:22",
            status=ScanStatus.PARTIAL,
            scan_timestamp="2026-01-01T00:00:00Z",
        )
        assert scan.is_verified is False

    def test_security_score_refuses_failed_scan(self):
        scan = ScanResult(
            image_reference="node:22", status=ScanStatus.ERROR, error_message="exit 1"
        )
        with pytest.raises(ValueError, match="Cannot score"):
            SecurityScore(DockerImage(name="node", tag="22"), scan)


class TestFinalInvariant:
    def _analysis(self, status: ScanStatus, timestamp: str = "2026-01-01T00:00:00Z"):
        return ImageAnalysis(
            image=DockerImage(name="node", tag="22-alpine"),
            scan=ScanResult(
                image_reference="node:22-alpine", status=status, scan_timestamp=timestamp
            ),
            security_score=100.0,
            tier="A",
            remediation_score=100,
        )

    def test_verified_analyses_pass(self):
        _assert_verified([self._analysis(ScanStatus.OK)])

    @pytest.mark.parametrize("status", [ScanStatus.ERROR, ScanStatus.TIMEOUT, ScanStatus.PARTIAL])
    def test_unverified_analysis_raises(self, status):
        with pytest.raises(UnverifiedRecommendationError, match="node:22-alpine"):
            _assert_verified([self._analysis(status)])

    def test_perfect_score_does_not_bypass_the_gate(self):
        # A score=100 / tier="A" row is exactly the shape a bad fallback
        # produced; the gate must reject it on scan status alone.
        bogus = self._analysis(ScanStatus.ERROR)
        assert bogus.security_score == 100.0
        assert bogus.tier == "A"
        with pytest.raises(UnverifiedRecommendationError):
            _assert_verified([bogus])

    def test_missing_timestamp_raises(self):
        with pytest.raises(UnverifiedRecommendationError):
            _assert_verified([self._analysis(ScanStatus.OK, timestamp="")])


class TestStaleCacheIsRevalidated:
    @pytest.mark.asyncio
    async def test_cached_failed_scan_is_discarded(self):
        from dockerls.domain.interfaces.cache_store import CacheStoreInterface

        # Analysis cache entries are intentionally ineligible without a
        # canonical digest. Exercise stale-entry eviction with an identity
        # that can actually reach L2 rather than the mutable-tag cache miss
        # path tested elsewhere.
        cached_image = TAGS[0].model_copy(update={"digest": "sha256:" + "a" * 64})
        poisoned = ImageAnalysis(
            image=cached_image,
            scan=ScanResult(
                image_reference=cached_image.full_reference,
                status=ScanStatus.ERROR,
                error_message="exit 1",
                scan_timestamp="2026-01-01T00:00:00Z",
            ),
            security_score=100.0,
            tier="A",
            remediation_score=100,
        )

        class _Cache(CacheStoreInterface):
            def __init__(self, key):
                self.store = {key: poisoned.model_dump()}
                self.deleted: list[str] = []

            async def get(self, key):
                return self.store.get(key)

            async def set(self, key, value, ttl_seconds=86400):
                self.store[key] = value

            async def delete(self, key):
                self.deleted.append(key)
                self.store.pop(key, None)

            async def clear(self):
                self.store.clear()

        # A chave carrega um fingerprint das regras de ignore e do threat
        # intel; perguntá-la ao caso de uso evita testar o formato dela.
        use_case = _use_case(_CleanScanner(), repository=_Repo(tags=[cached_image]))
        key = use_case._cache_key(cached_image)
        assert key is not None
        cache = _Cache(key)
        use_case._cache = cache
        result = await use_case.execute("node")

        assert key in cache.deleted
        # Re-scanned cleanly, so it is recommended on the fresh scan's merit.
        assert all(a.scan.is_verified for a in result.recommendations)


class TestHubTagVerification:
    @pytest.mark.asyncio
    async def test_tag_missing_on_hub_is_dropped(self):
        repo = _Repo(existing_tags={"22-alpine"})
        result = await _use_case(_CleanScanner(), repository=repo).execute("node")

        refs = {a.image.full_reference for a in result.recommendations}
        assert refs == {"node:22-alpine"}
        assert any(u.status == "TAG_NOT_FOUND" for u in result.unverified)

    @pytest.mark.asyncio
    async def test_recommendations_carry_a_hub_url(self):
        result = await _use_case(_CleanScanner()).execute("node")

        assert result.recommendations
        for a in result.recommendations:
            assert a.hub_url.startswith("https://hub.docker.com/_/node?tab=tags&name=")
            assert a.hub_tag_verified is True

    @pytest.mark.asyncio
    async def test_hub_check_can_be_disabled(self):
        repo = _Repo(existing_tags=set())
        result = await _use_case(_CleanScanner(), repository=repo, verify_hub_tags=False).execute(
            "node"
        )

        assert len(result.recommendations) == len(TAGS)
        assert all(a.hub_tag_verified is None for a in result.recommendations)


class TestCrossValidation:
    @pytest.mark.asyncio
    async def test_material_divergence_is_flagged(self):
        from dockerls.application.services.cross_validation import CrossValidator

        vulns = [
            Vulnerability(cve_id=f"CVE-{i}", severity=Severity.HIGH, fixed_version="1.0")
            for i in range(10)
        ]

        class _Primary(ScannerInterface):
            async def scan(self, image_reference):
                return ScanResult(
                    image_reference=image_reference,
                    scanner="trivy",
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

            async def is_available(self):
                return True

        class _Secondary(ScannerInterface):
            async def scan(self, image_reference):
                return ScanResult(
                    image_reference=image_reference,
                    scanner="grype",
                    vulnerabilities=vulns,
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

            async def is_available(self):
                return True

        result = await _use_case(_Primary(), cross_validator=CrossValidator(_Secondary())).execute(
            "node"
        )

        assert result.recommendations
        for a in result.recommendations:
            # Asserted by substance rather than by wording: the message
            # names both scanners, what each found, and which findings are
            # disputed. Pinning the exact sentence would break every time
            # the explanation improves.
            assert "HIGH" in a.scan_divergence
            assert "trivy" in a.scan_divergence and "grype" in a.scan_divergence
            assert "10" in a.scan_divergence
            assert a.cross_validation == "MATERIAL_DIVERGENCE"

    @pytest.mark.asyncio
    async def test_small_difference_is_not_flagged(self):
        from dockerls.application.services.cross_validation import CrossValidator

        class _Secondary(ScannerInterface):
            async def scan(self, image_reference):
                return ScanResult(
                    image_reference=image_reference,
                    scanner="grype",
                    vulnerabilities=[
                        Vulnerability(cve_id="CVE-1", severity=Severity.HIGH),
                        Vulnerability(cve_id="CVE-2", severity=Severity.HIGH),
                    ],
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

            async def is_available(self):
                return True

        result = await _use_case(
            _CleanScanner(), cross_validator=CrossValidator(_Secondary())
        ).execute("node")

        assert result.recommendations
        assert all(a.scan_divergence == "" for a in result.recommendations)

    @pytest.mark.asyncio
    async def test_failed_secondary_scan_does_not_flag_divergence(self):
        from dockerls.application.services.cross_validation import CrossValidator

        class _BrokenSecondary(ScannerInterface):
            async def scan(self, image_reference):
                return ScanResult(
                    image_reference=image_reference,
                    scanner="grype",
                    status=ScanStatus.ERROR,
                    error_message="grype exited 1",
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

            async def is_available(self):
                return True

        result = await _use_case(
            _CleanScanner(), cross_validator=CrossValidator(_BrokenSecondary())
        ).execute("node")

        assert result.recommendations
        assert all(a.scan_divergence == "" for a in result.recommendations)


class TestPromotedCandidatesAreCrossValidated:
    """A cross-validation rodava sobre o top N *antes* do filtro de tags.

    Um candidato promovido para o lugar de outro descartado entrava na
    tabela sem nunca ter passado pelo segundo scanner -- ou seja, com a
    pontuação apresentada sem contestação justamente por não ter sido
    checada. Que é a garantia que o README dá para os melhores candidatos.
    """

    @pytest.mark.asyncio
    async def test_a_candidate_promoted_after_a_tag_drop_is_still_validated(self):
        from dockerls.application.services.cross_validation import CrossValidator

        # Onze tags: mais que TOP_N, para haver quem promover.
        tags = [DockerImage(name="node", tag=f"t{i}", is_official=True) for i in range(11)]
        # A primeira não existe no registry e será descartada.
        existing = {t.tag for t in tags[1:]}

        class _Secondary(ScannerInterface):
            def __init__(self):
                self.scanned: list[str] = []

            async def is_available(self):
                return True

            async def scan(self, image_reference):
                self.scanned.append(image_reference)
                return ScanResult(
                    image_reference=image_reference,
                    scanner="grype",
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

        secondary = _Secondary()
        result = await _use_case(
            _CleanScanner(),
            repository=_Repo(tags=tags, existing_tags=existing),
            cross_validator=CrossValidator(secondary),
        ).execute("node")

        recommended = {a.image.full_reference for a in result.recommendations}
        assert recommended, "nothing was recommended, the test proves nothing"
        # A tag inexistente não pode ter sobrado...
        assert "node:t0" not in recommended
        # ...e tudo que sobrou precisa ter sido cross-validado.
        assert recommended <= set(secondary.scanned)

    @pytest.mark.asyncio
    async def test_dropped_candidates_do_not_cost_a_secondary_scan(self):
        """Escanear quem vai ser descartado é trabalho jogado fora."""
        from dockerls.application.services.cross_validation import CrossValidator
        from dockerls.application.use_cases.recommend_images import TOP_N

        tags = [DockerImage(name="node", tag=f"t{i}", is_official=True) for i in range(11)]

        class _Secondary(ScannerInterface):
            def __init__(self):
                self.scanned: list[str] = []

            async def is_available(self):
                return True

            async def scan(self, image_reference):
                self.scanned.append(image_reference)
                return ScanResult(
                    image_reference=image_reference,
                    scanner="grype",
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                )

        secondary = _Secondary()
        await _use_case(
            _CleanScanner(),
            repository=_Repo(tags=tags, existing_tags={t.tag for t in tags[1:]}),
            cross_validator=CrossValidator(secondary),
        ).execute("node")

        assert len(secondary.scanned) <= TOP_N
