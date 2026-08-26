"""L4 -- tool authorization.

The layer that converts detection into containment.

L0-L3 decide how suspicious a request looks. L4 decides what it is permitted
to *do*, and that decision does not depend on a probability. An injection
that beats every detector still cannot reach ``send_email`` if the authority
behind the call is a fetched web page, because the rule is about provenance
rather than content.

L4's real work is establishing two facts the policy engine then judges:

  request_tainted   did untrusted content drive the decision to call this?
  tainted_args      do the argument values come out of untrusted spans?

Both are computed conservatively. Where provenance is ambiguous L4 resolves
toward tainted, because the cost of a false positive is a confirmation
prompt and the cost of a false negative is the incident.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..constants import AttackFamily, Decision, LayerName, Phase, Severity, TrustLevel
from ..pipeline.context import PipelineContext, ToolCall
from ..pipeline.verdict import Finding
from .base import Layer

#: Argument values shorter than this are not matched against untrusted text:
#: "1", "true" and "en" appear everywhere and would taint every call.
MIN_TAINT_MATCH = 8

#: Families that indicate untrusted content was actively steering tool use.
_STEERING_FAMILIES = {
    AttackFamily.TOOL_ABUSE,
    AttackFamily.EXFILTRATION,
    AttackFamily.INSTRUCTION_OVERRIDE,
    AttackFamily.INDIRECT,
}

_TOKEN_RE = re.compile(r"[A-Za-z0-9_.@:/-]{4,}")


class ToolGateLayer(Layer):
    name = LayerName.L4_TOOL_GATE
    phase = Phase.TOOL
    cost_ms = 2.0

    def should_run(self, ctx: PipelineContext) -> tuple[bool, str]:
        ok, reason = super().should_run(ctx)
        if not ok:
            return ok, reason
        if not ctx.tool_calls:
            return False, "no tool calls in this request"
        return True, ""

    def run(self, ctx: PipelineContext) -> list[Finding]:
        findings: list[Finding] = []
        untrusted_text = ctx.untrusted_text()
        request_trust = self._request_trust(ctx)
        steering = self._steering_evidence(ctx)

        for call in ctx.tool_calls:
            call.request_trust = request_trust
            call.tainted_args = self._taint_arguments(call, untrusted_text)
            call.request_tainted = self._is_request_tainted(call, untrusted_text, steering)

            verdict = ctx.engine.evaluate_tool(
                call.name,
                call.arguments,
                request_trust=call.request_trust,
                tainted_args=call.tainted_args,
                request_tainted=call.request_tainted,
                layer=self.name,
            )
            findings.extend(verdict.findings)

            if verdict.decision is not Decision.ALLOW:
                ctx.note(f"l4.blocked.{call.name}", verdict.decision.value)

        ctx.note("l4.request_trust", request_trust.name.lower())
        ctx.note("l4.evaluated", len(ctx.tool_calls))
        return findings

    # -- provenance reasoning -------------------------------------------

    @staticmethod
    def _request_trust(ctx: PipelineContext) -> TrustLevel:
        """The authority actually present in the conversation.

        Taken from principal turns (user, developer, system) only. Tool
        results are evidence, never authority -- counting them here would let
        a retrieved document raise the trust level of the request that
        retrieved it.
        """
        principals = [
            m.trust
            for m in ctx.messages
            if m.role.lower() in {"user", "system", "developer"}
        ]
        return max(principals) if principals else TrustLevel.UNTRUSTED

    def _steering_evidence(self, ctx: PipelineContext) -> bool:
        """Did earlier layers see untrusted content pushing toward tool use?"""
        for finding in ctx.verdict.findings:
            if finding.family in _STEERING_FAMILIES and finding.in_untrusted:
                return True
        return False

    def _taint_arguments(self, call: ToolCall, untrusted: str) -> dict[str, bool]:
        """Which arguments carry values lifted out of untrusted content?

        Substring containment rather than exact equality: a model
        paraphrases, reformats and concatenates, so an exfiltrated URL
        usually arrives embedded in a larger argument rather than verbatim.
        """
        if not untrusted:
            return {name: False for name in call.arguments}

        haystack = untrusted.lower()
        tainted: dict[str, bool] = {}
        for name, value in call.arguments.items():
            text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            tainted[name] = self._value_in(text, haystack)
        return tainted

    @staticmethod
    def _value_in(value: str, haystack_lower: str) -> bool:
        candidate = value.strip().lower()
        if len(candidate) >= MIN_TAINT_MATCH and candidate in haystack_lower:
            return True
        # Fall back to distinctive tokens: URLs, addresses and identifiers
        # survive reformatting even when the surrounding text does not.
        for token in _TOKEN_RE.findall(candidate):
            if len(token) >= MIN_TAINT_MATCH and token in haystack_lower:
                return True
        return False

    def _is_request_tainted(self, call: ToolCall, untrusted: str, steering: bool) -> bool:
        """Was the decision to make this call traceable to untrusted content?

        True when any of:
          * an earlier layer saw untrusted content steering toward tool use
          * the untrusted content names this tool
          * an argument value was lifted out of untrusted content
        """
        if steering:
            return True
        if untrusted and call.name.lower() in untrusted.lower():
            return True
        return any(call.tainted_args.values())
