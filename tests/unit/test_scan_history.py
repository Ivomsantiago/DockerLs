"""O histórico de contagem de vulnerabilidades: o que ele conta e o que ele se recusa a contar."""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.scan_history import (
    MAX_OBSERVATIONS,
    ScanHistory,
    ScanObservation,
    record,
)


def _obs(day: int, digest: str = "sha256:aaa", **counts: int) -> ScanObservation:
    return ScanObservation(digest=digest, observed_at=f"2026-01-{day:02d}T12:00:00+00:00", **counts)


class TestRecord:
    def test_first_observation_is_not_a_change(self) -> None:
        history = record(ScanHistory(reference="node:22"), _obs(1, critical=1))
        assert history.scans == 1
        assert history.latest is not None
        assert history.latest.critical == 1
        assert history.first_seen.startswith("2026-01-01")

    def test_identical_counts_on_the_same_digest_create_no_event(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, critical=2, high=3))
        after = record(history, _obs(5, critical=2, high=3))

        assert after is history
        assert len(after.observations) == 1

    def test_a_changed_count_is_recorded(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, critical=2))
        history = record(history, _obs(3, critical=5))

        assert history.scans == 2
        assert history.latest is not None
        assert history.latest.critical == 5

    def test_a_moved_digest_with_the_same_counts_is_still_recorded(self) -> None:
        """The digest is part of the identity of an observation: a tag that
        moved to a new digest is worth recording even if, by coincidence,
        the new image has the exact same vulnerability counts."""
        history = record(ScanHistory(reference="r"), _obs(1, digest="sha256:aaa", critical=2))
        history = record(history, _obs(3, digest="sha256:bbb", critical=2))

        assert history.scans == 2

    def test_an_empty_digest_never_enters(self) -> None:
        """Failing to resolve a digest is not an observation of anything."""
        history = record(ScanHistory(reference="r"), _obs(1, digest="   ", critical=1))
        assert history.is_empty

    def test_an_empty_history_never_fakes_stability(self) -> None:
        history = ScanHistory(reference="r")
        assert history.is_empty
        assert history.latest is None
        assert history.first_seen == ""
        assert "there is no history" in history.explain()

    def test_a_single_scan_has_nothing_to_compare_against(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, critical=1))
        assert "nothing to compare" in history.explain()

    def test_pruning_preserves_the_first_observation(self) -> None:
        history = ScanHistory(reference="r")
        for i in range(MAX_OBSERVATIONS + 5):
            history = record(history, _obs(1, digest=f"sha256:{i:03d}", critical=i))

        assert len(history.observations) == MAX_OBSERVATIONS
        assert history.observations[0].digest == "sha256:000"
        assert history.observations[-1].digest == f"sha256:{MAX_OBSERVATIONS + 4:03d}"

    def test_pruning_does_not_lose_the_scan_count(self) -> None:
        history = ScanHistory(reference="r")
        for i in range(MAX_OBSERVATIONS + 10):
            history = record(history, _obs(1, digest=f"sha256:{i:03d}", critical=i))

        assert history.scans == MAX_OBSERVATIONS + 10
        assert history.dropped == 10


class TestExplain:
    def test_an_increase_is_stated_with_its_sign(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, critical=2, high=1))
        history = record(history, _obs(5, critical=5, high=1))

        assert "critical +3" in history.explain()
        assert "high" not in history.explain()

    def test_a_decrease_is_stated_with_its_sign(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, high=10))
        history = record(history, _obs(5, high=4))

        assert "high -6" in history.explain()

    def test_an_unchanged_dimension_is_not_mentioned(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, critical=1, medium=5))
        history = record(history, _obs(2, critical=2, medium=5))

        assert "medium" not in history.explain()


class TestSerialization:
    def test_a_round_trip_preserves_the_counts(self) -> None:
        history = ScanHistory(reference="r")
        for i in range(MAX_OBSERVATIONS + 3):
            history = record(history, _obs(1, digest=f"sha256:{i:03d}", critical=i))

        restored = ScanHistory.from_dict("r", history.to_dict())

        assert restored.scans == history.scans
        assert restored.dropped == history.dropped
        assert restored.observations == history.observations

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "not a dict",
            {"observations": "not a list either"},
            {"observations": [{"digest": 7}]},
            {"observations": [{"digest": "   ", "observed_at": "x"}]},
            {"observations": [{"digest": "sha256:a", "observed_at": "x", "critical": -1}]},
            {"observations": [{"digest": "sha256:a", "observed_at": "x", "critical": True}]},
            {"observations": [None, 3, []]},
        ],
    )
    def test_invalid_cache_content_becomes_an_empty_history(self, raw: object) -> None:
        """The cache is content from outside this process; a corrupted entry
        must not take down the scan it is meant to enrich."""
        history = ScanHistory.from_dict("r", raw)
        assert history.is_empty

    def test_negative_dropped_count_from_the_cache_is_ignored(self) -> None:
        history = ScanHistory.from_dict("r", {"observations": [], "dropped_observations": -5})
        assert history.dropped == 0

    def test_a_valid_observation_survives_an_invalid_one_beside_it(self) -> None:
        history = ScanHistory.from_dict(
            "r",
            {
                "observations": [
                    {
                        "digest": "sha256:aaa",
                        "observed_at": "2026-01-01T12:00:00+00:00",
                        "critical": 2,
                    },
                    {"digest": None},
                ]
            },
        )
        assert history.observations == (
            ScanObservation(
                digest="sha256:aaa", observed_at="2026-01-01T12:00:00+00:00", critical=2
            ),
        )

    def test_the_explanation_is_included_in_the_document(self) -> None:
        history = record(ScanHistory(reference="r"), _obs(1, critical=1))
        history = record(history, _obs(9, critical=4))
        payload = history.to_dict()

        assert payload["scans"] == 2
        assert "critical +3" in str(payload["explanation"])
        assert len(payload["observations"]) == 2  # type: ignore[arg-type]
