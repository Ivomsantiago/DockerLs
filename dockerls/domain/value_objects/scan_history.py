"""How an image's vulnerability counts moved across scans over time.

`tag_history.py` answers "did the bytes behind this reference change";
this answers the question underneath it -- "when this reference was
scanned again, did the count of findings go up or down". Neither implies
the other: a tag can move to a new digest with fewer CVEs, or stay on the
exact same digest while the scanner's database learns about a new one
between two runs.

Same two choices as `tag_history.py`, for the same reasons:

* **Only a change enters.** Scanning the same reference twice with the
  same digest and the same counts is not a second event; recording it
  anyway would bury the actual changes in noise.
* **The first observation is never the one pruning drops.** It anchors
  "since when", and a history that starts at an arbitrary later point is
  a history that lies about how long it has been watching.

Nothing here claims a reference was ever *clean*: the history begins at
the first scan this tool happened to run, and whatever came before that is
unknown, not absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

#: Same ceiling as `tag_history.py`, for the same reason: enough
#: observations to see a trend, small enough that a whole fleet's history
#: does not turn the cache into a database by accident.
MAX_OBSERVATIONS = 24

#: The dimensions tracked and, in this order, reported when they change.
_FIELDS = ("critical", "high", "medium", "low", "total")


@dataclass(frozen=True)
class ScanObservation:
    """One scan's counts, and when this tool saw them."""

    digest: str
    observed_at: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0

    def counts(self) -> tuple[int, ...]:
        """The tracked dimensions as a tuple, in `_FIELDS` order -- for
        comparing two observations without naming every field."""
        return tuple(getattr(self, name) for name in _FIELDS)

    def to_dict(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "observed_at": self.observed_at,
            **{name: getattr(self, name) for name in _FIELDS},
        }

    @staticmethod
    def from_dict(raw: object) -> ScanObservation | None:
        """An observation from the cache, or `None` when the row is unusable.

        The cache is content from outside this call: a corrupted entry or
        one written by an earlier version must not take down a scan.
        """
        if not isinstance(raw, dict):
            return None
        digest = raw.get("digest")
        observed = raw.get("observed_at")
        if not isinstance(digest, str) or not isinstance(observed, str) or not digest.strip():
            return None
        counts: dict[str, int] = {}
        for name in _FIELDS:
            value = raw.get(name, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
            counts[name] = value
        return ScanObservation(digest=digest.strip(), observed_at=observed.strip(), **counts)


@dataclass(frozen=True)
class ScanHistory:
    """What is known about a reference's vulnerability counts, in order."""

    reference: str
    observations: tuple[ScanObservation, ...] = field(default_factory=tuple)
    #: Same accounting as `TagHistory.dropped`: observations pruned off the
    #: front, counted rather than silently forgotten.
    dropped: int = 0

    @property
    def is_empty(self) -> bool:
        return not self.observations

    @property
    def scans(self) -> int:
        """Total scans this history has ever recorded, pruned ones included."""
        return len(self.observations) + self.dropped

    @property
    def first_seen(self) -> str:
        return self.observations[0].observed_at if self.observations else ""

    @property
    def latest(self) -> ScanObservation | None:
        return self.observations[-1] if self.observations else None

    def explain(self) -> str:
        """The sentence that turns two counts into a fact worth reading."""
        if self.is_empty:
            return "first scan recorded for this reference: there is no history to compare against"
        if len(self.observations) == 1:
            return f"first scan recorded on {self.first_seen}; nothing to compare it to yet"

        previous, current = self.observations[-2], self.observations[-1]
        deltas = _describe_deltas(previous, current)
        if not deltas:
            return f"unchanged since the previous scan on {previous.observed_at}"
        return f"since {previous.observed_at}: " + ", ".join(deltas)

    def to_dict(self) -> dict[str, object]:
        return {
            "reference": self.reference,
            "scans": self.scans,
            "dropped_observations": self.dropped,
            "first_seen": self.first_seen,
            "explanation": self.explain(),
            "observations": [o.to_dict() for o in self.observations],
        }

    @staticmethod
    def from_dict(reference: str, raw: object) -> ScanHistory:
        """Reconstructs from the cache, discarding whatever does not parse.

        An unreadable history becomes an empty one -- which is honest:
        nothing usable is known about this reference. Never an exception:
        this is an extra on top of the scan, not something that may block it.
        """
        if not isinstance(raw, dict):
            return ScanHistory(reference=reference)
        entries = raw.get("observations")
        if not isinstance(entries, list):
            return ScanHistory(reference=reference)
        parsed = [o for o in (ScanObservation.from_dict(e) for e in entries) if o is not None]
        dropped = raw.get("dropped_observations")
        return ScanHistory(
            reference=reference,
            observations=tuple(parsed),
            dropped=dropped if isinstance(dropped, int) and dropped >= 0 else 0,
        )


def _describe_deltas(previous: ScanObservation, current: ScanObservation) -> list[str]:
    deltas = []
    for name in _FIELDS:
        change = getattr(current, name) - getattr(previous, name)
        if change:
            deltas.append(f"{name} {change:+d}")
    return deltas


def record(history: ScanHistory, observation: ScanObservation) -> ScanHistory:
    """The history with this observation incorporated.

    An observation whose digest and every count match the last one
    recorded changes nothing worth saying, so it is dropped -- the same
    rule `tag_history.record` applies to a tag that did not move.
    """
    if not observation.digest.strip():
        return history
    if history.observations:
        last = history.observations[-1]
        if last.digest == observation.digest and last.counts() == observation.counts():
            return history

    entries = (*history.observations, observation)
    dropped = history.dropped
    if len(entries) > MAX_OBSERVATIONS:
        dropped += len(entries) - MAX_OBSERVATIONS
        entries = (entries[0], *entries[-(MAX_OBSERVATIONS - 1) :])
    return replace(history, observations=entries, dropped=dropped)
