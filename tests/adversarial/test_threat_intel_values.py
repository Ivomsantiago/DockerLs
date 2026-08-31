"""A feed that answers with nonsense must not certify an image.

Three defects lived on the same path, and all three had the same shape: a
number arriving from a third party was trusted as a number, and the failure
direction was *toward safety*.

* `float("nan")` parses. NaN then propagated into the penalty sum, and the
  final `max(0.0, min(100.0, score))` answers **100.0** for a NaN input --
  every comparison against NaN is False, so the clamp returned its own
  bound. A malformed EPSS response therefore produced a perfect security
  score for an image full of CRITICALs.
* A negative probability *subtracts* from the penalty, so a feed answering
  `-5` raised the score of a worse image.
* A KEV response that parsed but carried three entries -- a proxy error
  page, a truncated transfer -- was accepted as the catalogue, and every
  CVE not among those three was then reported as `kev_status = FALSE`:
  "checked, not known to be exploited", asserted on the strength of a
  response that was never the catalogue.
"""

from __future__ import annotations

import math
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.integrations.threat_intel.client import (
    MIN_PLAUSIBLE_KEV_ENTRIES,
    ThreatIntelClient,
)


def _vuln(cve: str = "CVE-2024-0001", **kwargs) -> Vulnerability:
    return Vulnerability(cve_id=cve, severity=Severity.CRITICAL, **kwargs)


class TestProbabilitiesAreBounded:
    @pytest.mark.parametrize("hostile", ["nan", "inf", "-inf", -1.0, -0.5, 1.5, 1e30, "abc", None])
    def test_a_value_that_is_not_a_probability_becomes_no_signal(self, hostile):
        assert _vuln(epss_score=hostile).epss_score == 0.0
        assert _vuln(epss_percentile=hostile).epss_percentile == 0.0

    @pytest.mark.parametrize("ok", [0.0, 0.5, 1.0, "0.42"])
    def test_real_probabilities_survive(self, ok):
        assert _vuln(epss_score=ok).epss_score == float(ok)

    def test_the_bound_holds_when_rebuilt_from_a_cached_row(self):
        """The same entity is reconstructed from SQLite, where a row written
        before this check existed may still carry a bad value."""
        restored = Vulnerability.model_validate(
            {"cve_id": "CVE-2024-0001", "severity": "CRITICAL", "epss_score": float("nan")}
        )
        assert restored.epss_score == 0.0


class TestScoreCannotBeNaN:
    def _score(self, vulns: list[Vulnerability]) -> float:
        image = DockerImage(name="app", tag="1.0")
        scan = ScanResult(image_reference="app:1.0", status=ScanStatus.OK, vulnerabilities=vulns)
        return SecurityScore(image, scan).value

    def test_a_nan_epss_no_longer_yields_a_perfect_score(self):
        """The regression itself: before the fix this returned 100.0."""
        score = self._score([_vuln(epss_score=float("nan"))])
        assert math.isfinite(score)
        assert score < 100.0, "a CRITICAL finding must cost points whatever EPSS said"

    def test_a_negative_epss_cannot_buy_points_back(self):
        clean = self._score([_vuln()])
        hostile = self._score([_vuln(epss_score=-5.0)])
        assert hostile <= clean, "a feed answering -5 must not improve the score"

    def test_a_worse_image_never_scores_higher(self):
        one = self._score([_vuln("CVE-1")])
        two = self._score([_vuln("CVE-1"), _vuln("CVE-2", epss_score=float("nan"))])
        assert two <= one


class TestKevPlausibility:
    @pytest.mark.asyncio
    async def test_a_catalogue_too_small_to_be_real_is_not_an_answer(self):
        client = ThreatIntelClient()
        payload = {"vulnerabilities": [{"cveID": f"CVE-2024-{i:04d}"} for i in range(3)]}
        resp = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.known_exploited(["CVE-2024-0001"])
        assert result == set()
        assert client.kev_available is False, (
            "an implausible catalogue must leave exploitation status UNKNOWN, "
            "not assert that nothing is exploited"
        )

    @pytest.mark.asyncio
    async def test_a_full_catalogue_is_accepted(self):
        client = ThreatIntelClient()
        payload = {
            "vulnerabilities": [
                {"cveID": f"CVE-2024-{i:04d}"} for i in range(MIN_PLAUSIBLE_KEV_ENTRIES)
            ]
        }
        resp = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.known_exploited(["CVE-2024-0001", "CVE-2099-9999"])
        assert result == {"CVE-2024-0001"}
        assert client.kev_available is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "payload",
        [
            {"vulnerabilities": "not-a-list"},
            {"vulnerabilities": [None, 7, "x"]},
            {},
            {"vulnerabilities": []},
        ],
    )
    async def test_a_malformed_payload_is_a_failed_lookup(self, payload):
        client = ThreatIntelClient()
        resp = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False

    @pytest.mark.asyncio
    async def test_an_http_500_is_a_failed_lookup(self):
        client = ThreatIntelClient()
        resp = httpx.Response(500, text="upstream error", request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False

    @pytest.mark.asyncio
    async def test_a_timeout_is_a_failed_lookup(self):
        client = ThreatIntelClient()
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ReadTimeout("slow", request=httpx.Request("GET", "https://x"))
            ),
        ):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False

    @pytest.mark.asyncio
    async def test_invalid_json_is_a_failed_lookup(self):
        client = ThreatIntelClient()
        resp = httpx.Response(
            200, text="<html>captive portal</html>", request=httpx.Request("GET", "https://x")
        )
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False


class TestKevHttpErrorPaths:
    """Every failure mode a real feed can hand back -- not just "unreachable"
    -- must degrade `kev_status` to UNKNOWN, never to a false "not in KEV".
    `max_attempts=1` keeps each of these a sustained failure rather than
    exercising the retry policy, which has its own tests."""

    @pytest.mark.asyncio
    async def test_a_401_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(401, text="Unauthorized", request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False

    @pytest.mark.asyncio
    async def test_a_403_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(403, text="Forbidden", request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False

    @pytest.mark.asyncio
    async def test_a_503_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(
            503, text="Service Unavailable", request=httpx.Request("GET", "https://x")
        )
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False

    @pytest.mark.asyncio
    async def test_malformed_json_is_a_failed_lookup(self):
        """A 200 whose body is not valid JSON at all -- distinct from valid
        JSON with the wrong shape, covered above."""
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(
            200, text="{not valid json", request=httpx.Request("GET", "https://x")
        )
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            assert await client.known_exploited(["CVE-2024-0001"]) == set()
        assert client.kev_available is False


class TestEpssHttpErrorPaths:
    """Same failure modes, for the FIRST EPSS feed."""

    @pytest.mark.asyncio
    async def test_a_401_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(401, text="Unauthorized", request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}
        assert client.epss_available is False

    @pytest.mark.asyncio
    async def test_a_403_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(403, text="Forbidden", request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}
        assert client.epss_available is False

    @pytest.mark.asyncio
    async def test_a_503_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(
            503, text="Service Unavailable", request=httpx.Request("GET", "https://x")
        )
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}
        assert client.epss_available is False

    @pytest.mark.asyncio
    async def test_malformed_json_is_a_failed_lookup(self):
        client = ThreatIntelClient(max_attempts=1)
        resp = httpx.Response(
            200, text="{not valid json", request=httpx.Request("GET", "https://x")
        )
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}
        assert client.epss_available is False


class TestEpssParsing:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("hostile", ["nan", "-1", "2", "inf", "not-a-number"])
    async def test_an_implausible_score_is_dropped_rather_than_carried(self, hostile):
        client = ThreatIntelClient()
        payload = {"data": [{"cve": "CVE-2024-0001", "epss": hostile, "percentile": "0.5"}]}
        resp = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}
        assert client.epss_available is False, (
            "a batch whose only value was unusable is not a successful lookup"
        )

    @pytest.mark.asyncio
    async def test_an_implausible_percentile_does_not_discard_a_good_score(self):
        client = ThreatIntelClient()
        payload = {"data": [{"cve": "CVE-2024-0001", "epss": "0.4", "percentile": "nan"}]}
        resp = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {"CVE-2024-0001": 0.4}
        assert client.percentile_of("CVE-2024-0001") == 0.0
