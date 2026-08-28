"""Reading the audit log without reading all of it.

Two functions share one correctness claim: what they return must equal what
walking the whole file would have returned. The summariser folds new bytes
into counters it already holds; tail_audit seeks backward from the end. Both
replace an implementation that parsed the entire log to answer a question
about its last few records.

The interesting cases are the ways an append-only file is not actually
append-only from a reader's point of view -- a record caught half-written, a
file rotated out from under the offset, a block boundary landing mid-line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptwall.admin.replay import iter_audit, tail_audit
from promptwall.admin.summary import AuditSummariser


def record(**overrides) -> dict:
    base = {
        "ts": 1.0,
        "request_id": "r",
        "phase": "input",
        "decision": "allow",
        "risk": 0.0,
        "families": [],
        "findings": [],
        "layers": [],
    }
    base.update(overrides)
    return base


def write(path: Path, records: list[dict], *, mode: str = "w") -> None:
    with path.open(mode, encoding="utf-8") as handle:
        for row in records:
            handle.write(json.dumps(row) + "\n")


@pytest.fixture
def log(tmp_path) -> Path:
    return tmp_path / "audit.log"


def test_missing_file_summarises_to_nothing(log):
    """An empty console is a true statement about a log that does not exist."""
    snapshot = AuditSummariser(log).snapshot()
    assert snapshot["total"] == 0
    assert snapshot["recent"] == []


def test_counts_decisions_families_rules_and_layers(log):
    write(
        log,
        [
            record(request_id="a"),
            record(
                request_id="b",
                decision="block",
                risk=0.95,
                families=["exfiltration"],
                findings=[{"rule_id": "exf.send_data_to_url"}],
                layers=[{"layer": "l1_heuristics", "ran": True, "duration_ms": 2.0}],
            ),
            record(
                request_id="c",
                decision="block",
                risk=0.97,
                families=["exfiltration"],
                findings=[{"rule_id": "exf.send_data_to_url"}],
                layers=[{"layer": "l1_heuristics", "ran": True, "duration_ms": 4.0}],
            ),
        ],
    )
    snapshot = AuditSummariser(log).snapshot()

    assert snapshot["total"] == 3
    assert snapshot["decisions"] == {"allow": 1, "block": 2}
    assert snapshot["families"] == {"exfiltration": 2}
    assert snapshot["top_rules"][0] == {"rule_id": "exf.send_data_to_url", "hits": 2}
    assert snapshot["layer_latency_ms"]["l1_heuristics"] == 3.0
    assert [row["request_id"] for row in snapshot["recent"]] == ["c", "b", "a"]


def test_a_skipped_layer_is_not_counted_as_latency(log):
    """L3 is usually disabled. Averaging in its zero would misreport L3 as the
    fastest layer in the pipeline rather than as one that did not run."""
    write(
        log,
        [
            record(
                layers=[
                    {"layer": "l1_heuristics", "ran": True, "duration_ms": 4.0},
                    {"layer": "l3_judge", "ran": False, "skipped": "disabled"},
                ]
            )
        ],
    )
    latency = AuditSummariser(log).snapshot()["layer_latency_ms"]
    assert latency == {"l1_heuristics": 4.0}


def test_risk_lands_in_fixed_buckets(log):
    write(log, [record(risk=r) for r in (0.0, 0.09, 0.55, 0.95, 1.0)])
    histogram = AuditSummariser(log).snapshot()["risk_histogram"]
    counts = dict(zip(histogram["edges"], histogram["counts"], strict=True))
    assert counts[0.0] == 2  # 0.0 and 0.09
    assert counts[0.55] == 1
    assert counts[0.9] == 2  # 0.95 and 1.0


# --- the incremental part --------------------------------------------------


def test_appending_matches_a_from_scratch_read(log):
    """The whole basis for holding counters between requests."""
    write(log, [record(request_id=f"a{i}", risk=i / 20) for i in range(10)])
    summariser = AuditSummariser(log)
    summariser.snapshot()

    write(
        log,
        [
            record(
                request_id=f"b{i}",
                decision="block",
                risk=0.95,
                families=["indirect"],
                findings=[{"rule_id": "ind.note_to_ai"}],
                layers=[{"layer": "l1_heuristics", "ran": True, "duration_ms": 1.5}],
            )
            for i in range(5)
        ],
        mode="a",
    )

    incremental = summariser.snapshot()
    from_scratch = AuditSummariser(log).snapshot()
    assert incremental == from_scratch
    assert incremental["total"] == 15


def test_a_half_written_record_is_neither_counted_nor_lost(log):
    """A read can land mid-append. Consuming the partial line would count a
    truncated record now and skip the real one forever."""
    write(log, [record(request_id="whole")])
    summariser = AuditSummariser(log)
    assert summariser.snapshot()["total"] == 1

    with log.open("a", encoding="utf-8") as handle:
        handle.write('{"ts": 2, "decision": "block", "risk": 0.9, "request_id": "to')
    assert summariser.snapshot()["total"] == 1, "the torn line was counted early"

    with log.open("a", encoding="utf-8") as handle:
        handle.write('rn", "findings": [], "layers": []}\n')
    finished = summariser.snapshot()
    assert finished["total"] == 2, "the completed record was dropped"
    assert finished["recent"][0]["request_id"] == "torn"


def test_rotation_rebuilds_rather_than_trusting_the_offset(log):
    write(log, [record(request_id=f"old{i}") for i in range(20)])
    summariser = AuditSummariser(log)
    assert summariser.snapshot()["total"] == 20

    write(log, [record(request_id="fresh")])  # truncates
    rebuilt = summariser.snapshot()
    assert rebuilt["total"] == 1
    assert rebuilt["recent"][0]["request_id"] == "fresh"


def test_malformed_lines_are_skipped_without_stalling_the_offset(log):
    """One bad line must not wedge every later record out of the summary."""
    with log.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(record(request_id="a")) + "\n")
        handle.write("this is not json\n")
        handle.write("\n")
        handle.write(json.dumps(record(request_id="b")) + "\n")

    snapshot = AuditSummariser(log).snapshot()
    assert snapshot["total"] == 2
    assert [row["request_id"] for row in snapshot["recent"]] == ["b", "a"]


def test_the_feed_carries_rule_ids_but_not_finding_content(log):
    """The console needs to name the rule. Everything else in a finding is
    derived from the request, and has no business in a browser."""
    write(
        log,
        [
            record(
                findings=[
                    {"rule_id": "io.ignore_previous", "excerpt": "SECRET USER TEXT"}
                ]
            )
        ],
    )
    row = AuditSummariser(log).snapshot()["recent"][0]
    assert row["rules"] == ["io.ignore_previous"]
    assert "SECRET USER TEXT" not in json.dumps(row)


def test_limit_selects_the_newest_records(log):
    write(log, [record(request_id=f"r{i:03d}") for i in range(50)])
    recent = AuditSummariser(log).snapshot(limit=3)["recent"]
    assert [row["request_id"] for row in recent] == ["r049", "r048", "r047"]


# --- tail_audit ------------------------------------------------------------


def test_tail_matches_walking_the_whole_file(log):
    """The claim that justifies replacing the full read."""
    write(log, [record(request_id=f"r{i:04d}") for i in range(500)])
    everything = list(iter_audit(log, limit=100_000))
    for limit in (1, 7, 50, 499, 500):
        assert tail_audit(log, limit) == everything[-limit:], f"limit={limit}"


@pytest.mark.parametrize("block", [1, 7, 64, 4096])
def test_tail_is_correct_whatever_the_block_boundary(log, block):
    """Reading backward in blocks puts a boundary in the middle of a line.

    Only the *first* line in the assembled buffer can be a fragment, which is
    why the loop reads until it holds one more newline than it needs. A tiny
    block size forces many backward seeks and exercises that.
    """
    write(log, [record(request_id=f"r{i:03d}") for i in range(40)])
    expected = list(iter_audit(log, limit=1000))[-10:]
    assert tail_audit(log, 10, block=block) == expected


def test_tail_handles_a_limit_larger_than_the_file(log):
    rows = [record(request_id=f"r{i}") for i in range(3)]
    write(log, rows)
    assert tail_audit(log, 500) == rows


def test_tail_returns_a_final_record_with_no_trailing_newline(log):
    """A log flushed mid-line still has a complete record in it."""
    rows = [record(request_id=f"r{i}") for i in range(3)]
    log.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    assert tail_audit(log, 2) == rows[-2:]


def test_tail_on_a_missing_or_empty_file(log, tmp_path):
    assert tail_audit(tmp_path / "nope.log", 10) == []
    log.write_text("", encoding="utf-8")
    assert tail_audit(log, 10) == []


def test_tail_skips_malformed_lines(log):
    log.write_text(
        '{"request_id": "a"}\nnot json\n\n{"request_id": "b"}\n', encoding="utf-8"
    )
    assert tail_audit(log, 10) == [{"request_id": "a"}, {"request_id": "b"}]
