"""L1 -- signature matching.

Cheap, deterministic, explainable. L1 exists to catch the enormous volume of
unoriginal attacks (copied jailbreak prompts, template injections) at
microsecond cost, and to give every block a reason an operator can read
without consulting a model.

L1 scans three renderings of the same request:

  normalized  the L0 output -- the common case
  raw         in case normalization itself destroyed evidence
  decoded     each nested payload L0 unwrapped, scanned in isolation

A finding in decoded content inherits the trust of the span it was decoded
from, so a base64 blob inside a fetched page stays untrusted rather than
becoming an unlabelled string with no provenance.
"""

from __future__ import annotations

import re

from ..constants import LayerName, Phase, Severity, TrustLevel
from ..pipeline.context import PipelineContext
from ..pipeline.verdict import Finding
from ..taint.labels import TaintMap
from .base import Layer

#: Metalinguistic framing: text that talks *about* a phrase rather than
#: using it. "Translate this sentence: ...", "a user reported typing ...".
_QUOTING_CONTEXT = re.compile(
    r"(?i)\b(?:translat\w+|quot\w+|cit\w+|example|e\.g\.|for instance|report\w+|typed|said|wrote|says|writes|phrase|sentence|string|literal|means|meaning|explain\w*|describ\w+|what does|ticket|bug ?report|test (?:case|fixture|data)|documentation|article|paper|deck|training)\b"
)

_OPEN_QUOTES = ("'", '"', "`", "«", "“", "‘")
_CLOSE_QUOTES = ("'", '"', "`", "»", "”", "’")

#: How much a quoted match keeps. Raised from 0.2 after the adaptive attacker
#: (bench/adaptive_attacker.py) used quote framing to land 8 evasions against
#: this very discount.
#:
#: It is deliberately not zero and deliberately not tiny. Structurally,
#: "Translate this sentence: '<payload>'" is identical whether a student or
#: an attacker wrote it, so no amount of pattern work separates them. What
#: 0.35 buys is that a *lone* quoted phrase in a genuine question stays below
#: the review threshold, while a quoted payload carrying any other signal
#: still crosses it.
#:
#: The residual risk is accepted knowingly: quote framing also degrades the
#: attack itself, since a model asked to translate an injection usually
#: translates it. The controls that do not depend on this judgement -- taint
#: tracking and the L4 tool gate -- are unaffected either way.
_QUOTED_RETENTION = 0.35


def _retention_for(distinct_rules: int) -> float:
    """How much weight a quoted match keeps, given how much else is quoted.

    Quoting explains *a* suspicious phrase. It does not explain a pile of
    them. "Translate this sentence: '<override phrase>'" is a real request a
    real person makes; the same sentence whose quoted span also contains a
    system-prompt request and a persona jailbreak is not a translation
    exercise that happened to collect three unrelated attacks.

    So the discount is full strength for one rule and decays as corroboration
    accumulates, reaching nothing at three. One is deliberately unchanged --
    every hard negative in the corpus quotes exactly one phrase, and they are
    the cases this discount exists to protect.

    This is the structural signal the earlier note said pattern work could not
    provide. It is not about the wording, which really is identical either
    way; it is about how much the quoting is being asked to excuse.
    """
    return min(1.0, _QUOTED_RETENTION * max(1, distinct_rules))


def _looks_quoted(text: str, start: int, end: int) -> bool:
    """Is this match being *mentioned* rather than *used*?"""
    before = text[max(0, start - 3) : start].strip()
    after = text[end : end + 3].strip()
    if before.endswith(_OPEN_QUOTES) and after.startswith(_CLOSE_QUOTES):
        return True
    return bool(_QUOTING_CONTEXT.search(text[max(0, start - 90) : start]))


def _discount_quoted(findings: list[Finding], text: str) -> list[Finding]:
    """Downweight injection phrases that are being discussed, not issued.

    Scoped to USER trust and above, and that scope is the whole point.
    Quoting is a plausible explanation when a person is asking a question
    about prompt injection; it is NO defence at all when the text came from a
    retrieved document, where an attacker would simply wrap the payload in
    quotation marks to buy the discount. Untrusted content therefore keeps
    its full weight, and the taint and tool-gate layers remain the real
    control regardless.
    """
    quoted: list[Finding] = []
    for finding in findings:
        if finding.trust < TrustLevel.USER or finding.start < 0:
            continue
        # Rules that name a dangerous object rather than a phrasing opt out
        # in policy (Signature.quotable). Backticks around `cat ~/.ssh/id_rsa`
        # are how the payload is delivered, not evidence it is being
        # discussed, and the discount was cutting such a hit to a third of
        # its weight.
        if finding.meta.get("quotable") is False:
            continue
        if _looks_quoted(text, finding.start, finding.end):
            quoted.append(finding)

    retention = _retention_for(len({f.rule_id for f in quoted}))
    for finding in quoted:
        if retention < 1.0:
            finding.weight = round((finding.weight or 0.0) * retention, 6)
            finding.meta = {**finding.meta, "quoted_context": True}
        else:
            # Kept at full weight, but say why: an operator reading the audit
            # record should be able to see the discount was considered and
            # declined rather than never applied.
            finding.meta = {**finding.meta, "quoted_corroborated": True}
    return findings


class HeuristicsLayer(Layer):
    name = LayerName.L1_HEURISTICS
    phase = Phase.INPUT
    cost_ms = 4.0

    def run(self, ctx: PipelineContext) -> list[Finding]:
        engine = ctx.engine
        include_excerpt = ctx.settings.telemetry.audit_store_content
        findings: list[Finding] = []

        if ctx.normalized:
            findings.extend(
                engine.scan(
                    ctx.normalized,
                    ctx.normalized_taint,
                    layer=self.name,
                    offsets=ctx.offsets,
                    target="normalized",
                    include_excerpt=include_excerpt,
                )
            )

        # The raw pass catches the opposite failure: an attack that only
        # exists before normalization, such as a homoglyph-spelled domain
        # that folding turns into a legitimate-looking one.
        if ctx.raw_text and ctx.raw_text != ctx.normalized:
            findings.extend(
                engine.scan(
                    ctx.raw_text,
                    ctx.raw_taint,
                    layer=self.name,
                    target="raw",
                    include_excerpt=include_excerpt,
                )
            )

        findings.extend(self._scan_decoded(ctx, include_excerpt))
        deduped = _discount_quoted(_dedupe(findings), ctx.text)

        # Corroboration across independent renderings is itself evidence:
        # the same rule firing in both the plain text and a decoded payload
        # is far less likely to be an unlucky phrase.
        if len({f.meta.get("target") for f in deduped if f.meta.get("target")}) > 1:
            ctx.note("l1.multi_target", True)

        return deduped

    def _scan_decoded(self, ctx: PipelineContext, include_excerpt: bool) -> list[Finding]:
        out: list[Finding] = []
        taint = ctx.taint
        for payload in ctx.decoded:
            trust = taint.min_trust(payload.start, payload.end)
            payload_taint = TaintMap.uniform(
                len(payload.text), trust, f"decoded:{payload.scheme}"
            )
            hits = ctx.engine.scan(
                payload.text,
                payload_taint,
                layer=self.name,
                target="decoded",
                include_excerpt=include_excerpt,
            )
            for finding in hits:
                # Point the span at the encoded blob in the original text:
                # offsets inside a decoded string are meaningless to a caller.
                finding.start, finding.end = payload.start, payload.end
                if ctx.offsets is not None:
                    finding.orig_start, finding.orig_end = ctx.offsets.span_to_original(
                        payload.start, payload.end
                    )
                finding.source = f"decoded:{payload.scheme}"
                finding.meta = {
                    **finding.meta,
                    "scheme": payload.scheme,
                    "depth": payload.depth,
                }
                # An attack that had to be encoded to get here is more
                # deliberate than the same words typed in the clear.
                if payload.depth > 1 and finding.severity is not Severity.CRITICAL:
                    finding.weight = min(1.0, finding.weight * 1.25)
            out.extend(hits)
        return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse the same rule firing on the same span across renderings.

    Without this, one attack reported in raw, normalized and decoded form
    triples its own risk contribution and skews the noisy-OR aggregate.
    """
    best: dict[tuple[str, int, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.orig_start, finding.orig_end)
        current = best.get(key)
        if current is None or finding.weight > current.weight:
            best[key] = finding
    return sorted(best.values(), key=lambda f: (-f.weight, f.rule_id))
