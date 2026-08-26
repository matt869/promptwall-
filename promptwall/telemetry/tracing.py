"""Optional OpenTelemetry tracing.

Entirely optional and degrades to no-ops when the OTel packages are absent,
so importing this module never forces a dependency on a deployment that does
not want one.

Spans carry decisions, risk scores and layer timings -- never prompt content.
A trace exporter is another place prompts would leave the process, and the
audit log is the one place that is allowed to happen.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

try:  # pragma: no cover - exercised only when OTel is installed
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    AVAILABLE = True
except ImportError:
    AVAILABLE = False
    trace = None  # type: ignore[assignment]

_tracer: Any = None


def configure(settings) -> bool:
    """Install a tracer provider. Returns True when tracing is live."""
    global _tracer
    if not AVAILABLE or not settings.telemetry.tracing_enabled:
        return False

    resource = Resource.create(
        {"service.name": "promptwall", "service.version": _version()}
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=f"{settings.telemetry.otlp_endpoint}/v1/traces")
        )
    )
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("promptwall")
    return True


def _version() -> str:
    from .. import __version__  # noqa: PLC0415

    return __version__


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Start a span, or do nothing when tracing is off."""
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        yield current


def annotate_verdict(current: Any, verdict) -> None:
    """Attach verdict metadata to a span. Identifiers and counts only."""
    if current is None:
        return
    current.set_attribute("promptwall.decision", verdict.decision.value)
    current.set_attribute("promptwall.risk", verdict.risk)
    current.set_attribute("promptwall.advisory", verdict.advisory)
    current.set_attribute("promptwall.findings", len(verdict.findings))
    current.set_attribute("promptwall.policy_digest", verdict.policy_digest)
    if verdict.families:
        current.set_attribute("promptwall.families", ",".join(verdict.families))
