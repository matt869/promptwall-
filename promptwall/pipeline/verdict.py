"""Findings and verdicts: what the pipeline concluded, and why.

A Verdict has to serve three very different readers, which is why it carries
more than a decision:

  the caller        needs a decision and a reason they can act on
  the operator      needs enough detail to tune policy without a repro
  the incident      needs provenance and the exact policy digest, months later

Findings therefore keep their spans and trust levels rather than collapsing
to a score at the point of detection.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..constants import (
    SEVERITY_RANK,
    AttackFamily,
    Decision,
    LayerName,
    Phase,
    Severity,
    escalate,
)
from ..findings import Finding, aggregate_risk


@dataclass(slots=True)
class LayerReport:
    """Per-layer execution record. Powers the latency budget and the metrics."""

    layer: LayerName | str
    ran: bool = True
    skipped_reason: str = ""
    duration_ms: float = 0.0
    findings: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "layer": str(self.layer),
            "ran": self.ran,
            "duration_ms": round(self.duration_ms, 3),
            "findings": self.findings,
        }
        if self.skipped_reason:
            data["skipped"] = self.skipped_reason
        if self.error:
            data["error"] = self.error
        return data


@dataclass(slots=True)
class Transformation:
    """A rewrite applied to the traffic: redaction, spotlighting, stripping."""

    kind: str
    layer: LayerName | str
    detail: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "layer": str(self.layer), "detail": self.detail, "count": self.count}


@dataclass(slots=True)
class Verdict:
    """The pipeline's conclusion for one phase of one request."""

    phase: Phase = Phase.INPUT
    decision: Decision = Decision.ALLOW
    risk: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    layers: list[LayerReport] = field(default_factory=list)
    transformations: list[Transformation] = field(default_factory=list)

    request_id: str = ""
    session_id: str = ""
    policy_digest: str = ""
    policy_version: str = ""

    #: True when PromptWall would have acted but is running in monitor mode.
    advisory: bool = False
    started_at: float = field(default_factory=time.time)
    duration_ms: float = 0.0

    # -- mutation -------------------------------------------------------

    def add(self, *findings: Finding) -> Verdict:
        self.findings.extend(findings)
        return self

    def record(self, report: LayerReport) -> Verdict:
        self.layers.append(report)
        return self

    def transform(self, transformation: Transformation) -> Verdict:
        self.transformations.append(transformation)
        return self

    def raise_to(self, decision: Decision) -> Verdict:
        """Decisions only ratchet upward, never back down.

        A later layer must not be able to overturn an earlier block: that
        would make the outcome depend on layer ordering in a way an attacker
        could steer.
        """
        self.decision = escalate(self.decision, decision)
        return self

    def finalize(self, *, thresholds: Any = None, enforcing: bool = True) -> Verdict:
        """Compute the risk score and derive a decision from thresholds."""
        self.risk = aggregate_risk(self.findings)
        if thresholds is not None:
            if self.risk >= thresholds.block:
                self.raise_to(Decision.BLOCK)
            elif self.risk >= thresholds.review:
                self.raise_to(Decision.CHALLENGE)
        if not enforcing and self.decision is not Decision.ALLOW:
            self.advisory = True
        self.duration_ms = (time.time() - self.started_at) * 1000.0
        return self

    # -- queries --------------------------------------------------------

    @property
    def blocked(self) -> bool:
        """True only when enforcement is real. Monitor mode never blocks."""
        return self.decision is Decision.BLOCK and not self.advisory

    @property
    def top_finding(self) -> Finding | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: (SEVERITY_RANK[f.severity], f.weight))

    @property
    def families(self) -> list[str]:
        seen: dict[str, None] = {}
        for finding in self.findings:
            if finding.family is not AttackFamily.NONE:
                seen.setdefault(finding.family.value, None)
        return list(seen)

    def reason(self) -> str:
        """One human-readable sentence. What the caller sees on a block."""
        top = self.top_finding
        if top is None:
            return "no policy violation detected"
        where = f" in {top.source}" if top.source else ""
        return f"{top.message}{where} (rule {top.rule_id}, {top.severity.value})"

    # -- serialization --------------------------------------------------

    def to_client_dict(self) -> dict[str, Any]:
        """Deliberately thin.

        Detailed findings tell an attacker which rule fired and how close they
        came, turning every blocked request into a free oracle. Operators get
        the full record from the audit log, correlated by request_id.
        """
        return {
            "decision": self.decision.value,
            "reason": self.reason(),
            "request_id": self.request_id,
            "families": self.families,
            "advisory": self.advisory,
        }

    def to_audit_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "decision": self.decision.value,
            "risk": round(self.risk, 6),
            "advisory": self.advisory,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "duration_ms": round(self.duration_ms, 3),
            "families": self.families,
            "findings": [f.to_dict(include_excerpt=include_content) for f in self.findings],
            "layers": [layer.to_dict() for layer in self.layers],
            "transformations": [t.to_dict() for t in self.transformations],
        }
