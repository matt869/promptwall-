"""L5 -- output guard.

The last boundary before a response reaches the caller. Everything upstream
tries to stop an attack from succeeding; L5 assumes one did and limits what
leaves the building.

Three distinct concerns, deliberately not collapsed into one scan:

  credential and PII leakage   the model reciting something it was shown
  system prompt disclosure     the model reciting its own instructions
  zero-click exfiltration      markdown or HTML that leaks on render, with
                               no user interaction at all

The third is the one that makes an output guard non-negotiable. An image
whose URL embeds the conversation exfiltrates data the moment the response
is displayed, so refusing to *render* is the only control that works --
detecting the attack in the input would have had to be perfect.
"""

from __future__ import annotations

from ..constants import AttackFamily, Decision, LayerName, Phase, Severity, TrustLevel
from ..detectors.sysprompt_leak import detect_leak
from ..detectors.unsafe_markdown import scan_markdown
from ..pipeline.context import PipelineContext
from ..pipeline.verdict import Finding, Transformation
from .base import Layer


class OutputGuardLayer(Layer):
    name = LayerName.L5_OUTPUT_GUARD
    phase = Phase.OUTPUT
    cost_ms = 5.0

    def should_run(self, ctx: PipelineContext) -> tuple[bool, str]:
        ok, reason = super().should_run(ctx)
        if not ok:
            return ok, reason
        if not ctx.output_text:
            return False, "no output to inspect"
        return True, ""

    def run(self, ctx: PipelineContext) -> list[Finding]:
        findings: list[Finding] = []
        text = ctx.output_text

        # --- 1. secrets and PII -------------------------------------------
        result = ctx.engine.redact(text, output=True, layer=self.name)
        if result.changed:
            text = result.text
            findings.extend(result.findings)
            ctx.verdict.transform(
                Transformation(
                    kind="redaction",
                    layer=self.name,
                    detail=", ".join(sorted({f.rule_id for f in result.findings})),
                    count=result.count,
                )
            )
            ctx.verdict.raise_to(Decision.TRANSFORM)

        if result.drop:
            text = "[response withheld: contained material that must not be transmitted]"
            ctx.verdict.raise_to(Decision.BLOCK)

        # --- 2. system prompt disclosure ----------------------------------
        if ctx.system_prompt:
            leak = detect_leak(text, ctx.system_prompt)
            if leak.leaked:
                findings.append(
                    Finding(
                        layer=self.name,
                        rule_id="l5.sysprompt_leak",
                        message=(
                            f"response reproduces {leak.containment:.0%} of the system "
                            f"prompt (longest verbatim run {leak.longest_run} words)"
                        ),
                        severity=(
                            Severity.CRITICAL
                            if leak.severity_hint == "critical"
                            else Severity.HIGH
                        ),
                        family=AttackFamily.SYSPROMPT_LEAK,
                        trust=TrustLevel.THIRD_PARTY,
                        source="model_output",
                        confidence=min(1.0, leak.containment + 0.3),
                        meta={
                            "containment": leak.containment,
                            "longest_run": leak.longest_run,
                            "meta_phrase": leak.meta_phrase,
                        },
                    )
                )
                ctx.verdict.raise_to(Decision.BLOCK)

        # --- 3. zero-click exfiltration ------------------------------------
        hits = scan_markdown(text)
        auto = [h for h in hits if h.auto_fetch]
        for hit in hits:
            findings.append(
                Finding(
                    layer=self.name,
                    rule_id=f"l5.{hit.kind}",
                    message=f"{hit.kind} would leak on render: {hit.reason}",
                    severity=Severity.CRITICAL if hit.auto_fetch else Severity.MEDIUM,
                    family=AttackFamily.EXFILTRATION,
                    start=hit.start,
                    end=hit.end,
                    trust=TrustLevel.THIRD_PARTY,
                    source="model_output",
                    confidence=0.95 if hit.auto_fetch else 0.5,
                    # Defanging already neutralised this, so it does not by
                    # itself block: a page that merely makes the model emit an
                    # image URL would otherwise be a denial-of-service vector.
                    # The weight is still substantial, because emitting a
                    # beacon is strong evidence of an attack in progress and
                    # L6 should see it accumulate across the session.
                    weight=0.45 if hit.auto_fetch else 0.1,
                    meta={"url_host": hit.host, "reason": hit.reason},
                )
            )

        if auto:
            text = self._defang(text, auto)
            ctx.verdict.transform(
                Transformation(
                    kind="defang",
                    layer=self.name,
                    detail="auto-fetching markup neutralized",
                    count=len(auto),
                )
            )
            ctx.verdict.raise_to(Decision.TRANSFORM)

        ctx.output_text = text
        return findings

    @staticmethod
    def _defang(text: str, hits) -> str:
        """Neutralize auto-fetching markup while keeping the response readable.

        Rewritten rather than deleted: the user should still see that the
        model tried to emit something, and an operator reading the audit log
        needs to know what it was.
        """
        for hit in sorted(hits, key=lambda h: -h.start):
            replacement = f"[blocked {hit.kind}: {hit.reason}]"
            text = text[: hit.start] + replacement + text[hit.end :]
        return text
