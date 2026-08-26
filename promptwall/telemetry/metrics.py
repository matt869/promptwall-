"""Prometheus metrics.

Label cardinality is the thing to get right. Layer names, decisions and
attack families are bounded sets and make good labels. Rule ids are bounded
by the policy file and are acceptable. Anything derived from user input --
tool names from an arbitrary client, hostnames, model ids -- is not, and is
either omitted or bucketed.
"""

from __future__ import annotations

from typing import Any

try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
    from prometheus_client.exposition import CONTENT_TYPE_LATEST

    AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain"

#: Buckets tuned for a gateway that must stay inside a ~120ms input budget.
#: The default Prometheus buckets top out far too coarsely to show whether
#: that budget is being respected.
LATENCY_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


class Metrics:
    """All PromptWall metrics, on a private registry."""

    def __init__(self, registry: Any = None) -> None:
        self.enabled = AVAILABLE
        if not AVAILABLE:
            return
        self.registry = registry or CollectorRegistry()

        self.requests = Counter(
            "promptwall_requests_total",
            "Requests evaluated.",
            ["phase", "decision", "advisory"],
            registry=self.registry,
        )
        self.findings = Counter(
            "promptwall_findings_total",
            "Findings raised, by layer and severity.",
            ["layer", "severity", "family"],
            registry=self.registry,
        )
        self.rule_hits = Counter(
            "promptwall_rule_hits_total",
            "Signature and policy rule hits.",
            ["rule_id"],
            registry=self.registry,
        )
        self.blocked_tools = Counter(
            "promptwall_tool_decisions_total",
            "Tool authorization outcomes.",
            ["decision", "reason"],
            registry=self.registry,
        )
        self.pipeline_latency = Histogram(
            "promptwall_pipeline_seconds",
            "End-to-end pipeline latency per phase.",
            ["phase"],
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.layer_latency = Histogram(
            "promptwall_layer_seconds",
            "Per-layer latency.",
            ["layer"],
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.layer_skips = Counter(
            "promptwall_layer_skips_total",
            "Layers skipped, by reason class.",
            ["layer", "reason"],
            registry=self.registry,
        )
        self.upstream_latency = Histogram(
            "promptwall_upstream_seconds",
            "Upstream provider latency.",
            ["provider", "outcome"],
            registry=self.registry,
        )
        self.risk = Histogram(
            "promptwall_risk_score",
            "Distribution of aggregate risk scores.",
            buckets=(0.0, 0.1, 0.25, 0.4, 0.55, 0.7, 0.8, 0.9, 0.95, 1.0),
            registry=self.registry,
        )
        self.policy_version = Gauge(
            "promptwall_policy_reloads_total",
            "Successful policy reloads since start.",
            registry=self.registry,
        )
        self.degraded = Gauge(
            "promptwall_degraded",
            "1 when a non-advisory layer is unavailable.",
            registry=self.registry,
        )

    # -- recording -------------------------------------------------------

    def record_verdict(self, verdict) -> None:
        if not self.enabled:
            return
        self.requests.labels(
            phase=verdict.phase.value,
            decision=verdict.decision.value,
            advisory=str(verdict.advisory).lower(),
        ).inc()
        self.pipeline_latency.labels(phase=verdict.phase.value).observe(
            verdict.duration_ms / 1000.0
        )
        self.risk.observe(verdict.risk)

        for finding in verdict.findings:
            self.findings.labels(
                layer=str(finding.layer),
                severity=finding.severity.value,
                family=finding.family.value,
            ).inc()
            self.rule_hits.labels(rule_id=finding.rule_id).inc()

        for report in verdict.layers:
            if report.ran:
                self.layer_latency.labels(layer=str(report.layer)).observe(
                    report.duration_ms / 1000.0
                )
            elif report.skipped_reason:
                self.layer_skips.labels(
                    layer=str(report.layer), reason=_skip_class(report.skipped_reason)
                ).inc()

    def record_tool(self, decision: str, reason: str) -> None:
        if self.enabled:
            self.blocked_tools.labels(decision=decision, reason=reason).inc()

    def record_upstream(self, provider: str, outcome: str, seconds: float) -> None:
        if self.enabled:
            self.upstream_latency.labels(provider=provider, outcome=outcome).observe(seconds)

    def set_degraded(self, degraded: bool) -> None:
        if self.enabled:
            self.degraded.set(1 if degraded else 0)

    def render(self) -> tuple[bytes, str]:
        if not self.enabled:
            return b"# prometheus_client is not installed\n", CONTENT_TYPE_LATEST
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


def _skip_class(reason: str) -> str:
    """Bucket free-text skip reasons into a bounded label set."""
    low = reason.lower()
    if "budget" in low or "remaining" in low:
        return "budget"
    if "disabled" in low:
        return "disabled"
    if "no " in low or "empty" in low:
        return "not_applicable"
    return "other"


_metrics: Metrics | None = None


def get_metrics() -> Metrics:
    global _metrics
    if _metrics is None:
        _metrics = Metrics()
    return _metrics


def reset_metrics() -> None:
    global _metrics
    _metrics = None
