"""L0 -- normalization and decoding.

Runs first and unconditionally, because every later layer is only as good as
the text it is handed. An attacker who can keep ``ignore previous
instructions`` from *looking* like that string defeats L1 entirely and
degrades L2, without ever engaging with the detection logic.

L0 produces three things:

  ctx.normalized        NFKC-folded, invisibles stripped, confusables mapped
  ctx.offsets           normalized -> raw offset mapping, so findings can be
                        reported and redacted against what the caller sent
  ctx.decoded           nested payloads, each scanned separately by L1

Normalization never *replaces* the raw text. Both are kept, because a
detection has to be explainable against the original bytes.
"""

from __future__ import annotations

from ..constants import AttackFamily, LayerName, Phase, Severity, TrustLevel
from ..detectors.encoding import decode_all, normalize_text
from ..pipeline.context import PipelineContext
from ..pipeline.verdict import Finding
from ..taint.labels import OffsetMap, OffsetMapBuilder
from .base import Layer


class NormalizeLayer(Layer):
    name = LayerName.L0_NORMALIZE
    phase = Phase.INPUT
    cost_ms = 2.0

    def run(self, ctx: PipelineContext) -> list[Finding]:
        raw = ctx.raw_text
        if not raw:
            return []

        normalized, report = normalize_text(raw)
        ctx.normalized = normalized

        # Build an offset map. Normalization is not length-preserving, so
        # this is how a finding at normalized[i] gets reported against the
        # caller's original bytes.
        ctx.offsets = _build_offsets(raw, normalized)
        if ctx.raw_taint is not None:
            ctx.normalized_taint = ctx.raw_taint.project(ctx.offsets, len(normalized))

        findings: list[Finding] = []

        # Invisible characters are never innocent in an LLM prompt. They have
        # no rendering, so no human put them there for a human to read.
        if report.invisible_removed:
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id="l0.invisible_chars",
                    message=(
                        f"{report.invisible_removed} invisible or control characters "
                        f"removed before analysis"
                    ),
                    severity=Severity.HIGH if report.invisible_removed > 3 else Severity.MEDIUM,
                    family=AttackFamily.ENCODING,
                    trust=ctx.lowest_trust,
                    confidence=0.9,
                    meta={"count": report.invisible_removed},
                )
            )

        if report.confusables_folded:
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id="l0.confusables",
                    message=(
                        f"{report.confusables_folded} lookalike characters folded to ASCII"
                    ),
                    severity=Severity.MEDIUM if report.confusables_folded > 2 else Severity.LOW,
                    family=AttackFamily.ENCODING,
                    trust=ctx.lowest_trust,
                    confidence=0.7,
                    meta={"count": report.confusables_folded},
                )
            )

        # Decode anything the developer did not author. The floor is USER,
        # not THIRD_PARTY: a user pasting a base64 blob that decodes to an
        # override is still an attack, and scoping decoding to retrieved
        # content alone made every direct encoded attack invisible.
        # DEVELOPER and SYSTEM stay exempt, since decoding a developer's own
        # config blob and scanning it for injection phrasings reliably
        # manufactures false positives.
        decoded = self._decode_untrusted(ctx, normalized)
        ctx.decoded = decoded
        if decoded:
            deepest = max(d.depth for d in decoded)
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id="l0.encoded_payload",
                    message=(
                        f"{len(decoded)} encoded payload(s) decoded "
                        f"({', '.join(sorted({d.scheme for d in decoded}))})"
                    ),
                    severity=Severity.MEDIUM if deepest > 1 else Severity.LOW,
                    family=AttackFamily.ENCODING,
                    trust=ctx.lowest_trust,
                    confidence=0.6,
                    meta={
                        "count": len(decoded),
                        "max_depth": deepest,
                        "schemes": sorted({d.scheme for d in decoded}),
                    },
                )
            )

        ctx.note("l0.report", report)
        return findings

    def _decode_untrusted(self, ctx: PipelineContext, normalized: str):
        taint = ctx.normalized_taint
        if taint is None:
            return decode_all(normalized)

        out = []
        for span in taint.regions_at_or_below(TrustLevel.USER):
            chunk = normalized[span.start : span.end]
            for decoded in decode_all(chunk):
                decoded.start += span.start
                decoded.end += span.start
                out.append(decoded)
        return out


def _build_offsets(raw: str, normalized: str) -> OffsetMap:
    """Align normalized text back to the raw text.

    A real character-level alignment would need an edit-distance pass over
    every request, which is not affordable here. Instead we anchor on the
    runs that survived normalization unchanged and interpolate across the
    rewritten stretches. Interpolation is why OffsetMap.span_to_original
    widens outward: an approximate mapping must err toward redacting one
    character too many, never one too few.
    """
    builder = OffsetMapBuilder()
    ri = ni = 0
    raw_len, norm_len = len(raw), len(normalized)

    while ni < norm_len and ri < raw_len:
        if raw[ri] == normalized[ni]:
            start_r, start_n = ri, ni
            while ri < raw_len and ni < norm_len and raw[ri] == normalized[ni]:
                ri += 1
                ni += 1
            builder.emit(normalized[start_n:ni], start_r, ri)
            continue

        # Diverged. Find the next character that realigns the two streams.
        probe_n = ni + 1
        anchor = -1
        while probe_n < min(norm_len, ni + 64):
            found = raw.find(normalized[probe_n], ri)
            if found != -1 and found - ri < 256:
                anchor = found
                break
            probe_n += 1

        if anchor == -1:
            builder.emit(normalized[ni:], ri, raw_len)
            return builder.build()

        builder.emit(normalized[ni:probe_n], ri, anchor)
        ri, ni = anchor, probe_n

    if ni < norm_len:
        builder.emit(normalized[ni:], min(ri, raw_len), raw_len)
    return builder.build()
