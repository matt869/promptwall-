"""Rolling up the audit log for the console.

The obvious implementation re-reads the whole file per request, and that is
what this replaced. It is fine at a few hundred records and untenable at the
size an audit log actually reaches: 100k records is ~24 MB and ~900 ms to
parse, the dashboard polls every five seconds, and the endpoint is served
from the event loop -- so a console left open on a second monitor would stall
the gateway it is monitoring, repeatedly, for seven times its own input
latency budget.

So the summariser is incremental. It remembers how far into the file it has
read and folds only the new bytes into counters it already holds. Steady
state costs the length of one refresh interval of traffic, not the length of
the log.

Two things make that safe rather than merely fast:

*Partial lines.* A record can be half-written when the read lands. Only bytes
up to the final newline are consumed, so the remainder is picked up whole on
the next pass rather than parsed as a truncated record and skipped forever.

*Rotation.* If the file shrinks or the run of bytes we already consumed no
longer exists, the counters are rebuilt from scratch. Silently continuing
from a stale offset would produce a summary of a file that no longer exists.
"""

from __future__ import annotations

import json
import threading
from collections import Counter, deque
from pathlib import Path
from typing import Any

#: Bucket edges for the risk histogram. Fixed rather than derived from the
#: data: a histogram whose axis moves cannot be compared with yesterday's.
RISK_EDGES: tuple[float, ...] = (0.0, 0.1, 0.25, 0.4, 0.55, 0.7, 0.8, 0.9)

#: How many recent records to retain. The endpoint's own cap.
RECENT_MAX = 2000

#: Fields carried into the feed. Deliberately not the findings themselves --
#: the console needs rule ids, and everything else in a finding is content.
RECENT_FIELDS = (
    "ts",
    "request_id",
    "phase",
    "decision",
    "risk",
    "advisory",
    "families",
    "duration_ms",
)


def _bucket(risk: float) -> int:
    """Index of the histogram bucket a score falls in."""
    for i in range(len(RISK_EDGES) - 1, -1, -1):
        if risk >= RISK_EDGES[i]:
            return i
    return 0


class AuditSummariser:
    """Incremental aggregate over one audit file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self._offset = 0
        self._total = 0
        self._decisions: Counter[str] = Counter()
        self._families: Counter[str] = Counter()
        self._rules: Counter[str] = Counter()
        # Durations are floats, so a Counter is the wrong container here.
        self._layer_total: dict[str, float] = {}
        self._layer_count: Counter[str] = Counter()
        self._histogram = [0] * len(RISK_EDGES)
        self._recent: deque[dict[str, Any]] = deque(maxlen=RECENT_MAX)

    # -- ingest ----------------------------------------------------------

    def _fold(self, record: dict[str, Any]) -> None:
        self._total += 1
        self._decisions[str(record.get("decision", "unknown"))] += 1

        for family in record.get("families") or []:
            self._families[str(family)] += 1
        for finding in record.get("findings") or []:
            self._rules[str(finding.get("rule_id", "?"))] += 1
        for layer in record.get("layers") or []:
            if layer.get("ran"):
                name = str(layer.get("layer"))
                self._layer_total[name] = self._layer_total.get(name, 0.0) + float(
                    layer.get("duration_ms") or 0.0
                )
                self._layer_count[name] += 1

        risk = record.get("risk")
        if isinstance(risk, int | float):
            self._histogram[_bucket(float(risk))] += 1

        row = {key: record.get(key) for key in RECENT_FIELDS}
        row["rules"] = [str(f.get("rule_id")) for f in (record.get("findings") or [])][:6]
        self._recent.append(row)

    def _catch_up(self) -> None:
        """Fold whatever has been appended since the last pass."""
        try:
            size = self.path.stat().st_size
        except OSError:
            # No log yet, or it went away. Report nothing rather than raising:
            # an empty console is a true statement about an empty log.
            self._reset()
            return

        if size < self._offset:
            # Truncated or rotated under us.
            self._reset()

        if size == self._offset:
            return

        with self.path.open("rb") as handle:
            handle.seek(self._offset)
            chunk = handle.read(size - self._offset)

        end = chunk.rfind(b"\n")
        if end == -1:
            # A single record still being written. Leave the offset alone.
            return

        for line in chunk[: end + 1].splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(record, dict):
                self._fold(record)

        self._offset += end + 1

    # -- report ----------------------------------------------------------

    def snapshot(self, limit: int = 200) -> dict[str, Any]:
        with self._lock:
            self._catch_up()
            recent = list(self._recent)[-limit:][::-1]
            return {
                "total": self._total,
                "decisions": dict(self._decisions),
                "families": dict(self._families.most_common(12)),
                "top_rules": [
                    {"rule_id": rule, "hits": hits}
                    for rule, hits in self._rules.most_common(12)
                ],
                "risk_histogram": {
                    "edges": list(RISK_EDGES),
                    "counts": list(self._histogram),
                },
                "layer_latency_ms": {
                    name: round(self._layer_total[name] / self._layer_count[name], 3)
                    for name in sorted(self._layer_count)
                    if self._layer_count[name]
                },
                "recent": recent,
            }


def get_summariser(app_state: Any, path: str | Path) -> AuditSummariser:
    """One summariser per app, rebuilt if the configured path changes."""
    existing = getattr(app_state, "audit_summary", None)
    if existing is None or existing.path != Path(path):
        existing = AuditSummariser(path)
        app_state.audit_summary = existing
    return existing
