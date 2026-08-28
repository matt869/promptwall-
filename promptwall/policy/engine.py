"""The policy runtime: matching, redaction and tool authorization.

Stateless with respect to a request. Everything it needs comes from the
PolicyBundle it was built with, so an engine is cheap to construct, safe to
share across threads, and trivially swappable when policy reloads.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import regex

from ..constants import (
    AttackFamily,
    Decision,
    LayerName,
    RedactionMode,
    Severity,
    TrustLevel,
)
from ..findings import Finding
from ..taint.labels import OffsetMap, TaintMap
from .schema import (
    PolicyBundle,
    RedactionRule,
    Signature,
    ToolRule,
)

#: Per-pattern wall-clock ceiling. A hostile or merely sloppy rule must not
#: be able to stall the gateway.
REGEX_TIMEOUT_S = 0.05

#: Cap on matches recorded per rule. A page with 10,000 hits is one finding
#: worth acting on, not 10,000 audit records.
MAX_HITS_PER_RULE = 25

_URL_RE = regex.compile(r"https?://([^\s/:?#]+)", regex.IGNORECASE)


def luhn_valid(value: str) -> bool:
    """Luhn checksum, used to keep the card-number rule from eating IDs.

    The card pattern is deliberately loose, so without this it would fire on
    order numbers and long digit strings. A redactor that mangles ordinary
    traffic is a redactor operators switch off.
    """
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


VALIDATORS = {"luhn": luhn_valid}


@dataclass(slots=True)
class RedactionResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    count: int = 0
    #: True when a DROP-mode rule fired and the whole payload must be discarded.
    drop: bool = False

    @property
    def changed(self) -> bool:
        return self.count > 0


@dataclass(slots=True)
class ToolVerdict:
    decision: Decision = Decision.ALLOW
    findings: list[Finding] = field(default_factory=list)
    rule: str = ""
    #: Arguments whose values were rewritten before the call is allowed.
    sanitized_args: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.TRANSFORM)


def _meta(sig: Signature, target: str, hits: int) -> dict[str, Any]:
    """Per-finding metadata.

    ``target`` is recorded unconditionally: L1 treats the same rule firing in
    two different renderings of the request as corroboration, and it cannot
    do that if the rendering is only reported for rules that happened to
    match more than once.
    """
    meta: dict[str, Any] = {"target": target}
    if hits > 1:
        meta["hits"] = hits
    if not sig.quotable:
        meta["quotable"] = False
    return meta


def _excerpt(text: str, start: int, end: int, pad: int = 24, limit: int = 160) -> str:
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    snippet = text[lo:hi].replace("\n", "\n")
    return snippet[:limit]


class PolicyEngine:
    """Evaluates a PolicyBundle against text, tool calls and model output."""

    def __init__(self, bundle: PolicyBundle) -> None:
        self.bundle = bundle
        self._sig_cache: dict[str, regex.Pattern] = {}
        self._red_cache: dict[str, regex.Pattern] = {}

    # -- compiled-pattern caches ----------------------------------------

    def _sig_pattern(self, sig: Signature) -> regex.Pattern:
        cached = self._sig_cache.get(sig.id)
        if cached is None:
            cached = sig.compiled()
            self._sig_cache[sig.id] = cached
        return cached

    def _red_pattern(self, rule: RedactionRule) -> regex.Pattern:
        cached = self._red_cache.get(rule.id)
        if cached is None:
            cached = rule.compiled()
            self._red_cache[rule.id] = cached
        return cached

    # -- signature matching ---------------------------------------------

    def scan(
        self,
        text: str,
        taint: TaintMap | None = None,
        *,
        layer: LayerName | str = LayerName.L1_HEURISTICS,
        offsets: OffsetMap | None = None,
        target: str = "normalized",
        include_excerpt: bool = False,
        signatures: Iterable[Signature] | None = None,
    ) -> list[Finding]:
        """Match signatures against ``text``, gated by provenance.

        ``taint`` is what makes this more than grep. A rule scoped to
        ``max_trust: third_party`` fires only where the matched window's
        lowest trust is at or below that, so the same phrase can be ignored
        in a system prompt and treated as critical in a fetched page.
        """
        if not text:
            return []

        findings: list[Finding] = []
        rules = list(signatures) if signatures is not None else self.bundle.signatures.enabled()

        for sig in rules:
            if not self._targets(sig, target):
                continue
            pattern = self._sig_pattern(sig)
            try:
                matches = list(self._finditer(pattern, text))
            except TimeoutError:
                # Treat a runaway rule as a policy defect, not a request
                # failure: record it and keep scanning the others.
                findings.append(
                    Finding(
                        layer=layer,
                        rule_id=sig.id,
                        message=f"signature {sig.id} exceeded its evaluation budget",
                        severity=Severity.LOW,
                        family=AttackFamily.NONE,
                        confidence=0.0,
                        weight=0.0,
                        meta={"error": "regex_timeout"},
                    )
                )
                continue

            if len(matches) < sig.min_hits:
                continue

            for match in matches[:MAX_HITS_PER_RULE]:
                start, end = match.span()
                trust = taint.min_trust(start, end) if taint else TrustLevel.UNTRUSTED
                if trust > sig.max_trust:
                    continue

                orig_start, orig_end = (
                    offsets.span_to_original(start, end) if offsets else (start, end)
                )
                span = taint.span_at(start) if taint else None
                findings.append(
                    Finding(
                        layer=layer,
                        rule_id=sig.id,
                        message=sig.description or f"matched signature {sig.id}",
                        severity=sig.severity,
                        family=sig.family,
                        start=start,
                        end=end,
                        orig_start=orig_start,
                        orig_end=orig_end,
                        trust=trust,
                        source=span.source if span else "",
                        confidence=1.0,
                        weight=sig.effective_weight,
                        excerpt=_excerpt(text, start, end) if include_excerpt else "",
                        meta=_meta(sig, target, len(matches)),
                    )
                )
        return findings

    @staticmethod
    def _targets(sig: Signature, target: str) -> bool:
        return {
            "raw": sig.targets.raw,
            "normalized": sig.targets.normalized,
            "decoded": sig.targets.decoded,
        }.get(target, True)

    @staticmethod
    def _finditer(pattern: regex.Pattern, text: str):
        """finditer with a wall-clock ceiling across the whole scan."""
        pos = 0
        length = len(text)
        while pos <= length:
            match = pattern.search(text, pos, timeout=REGEX_TIMEOUT_S)
            if match is None:
                return
            yield match
            pos = match.end() + 1 if match.end() == match.start() else match.end()


    # -- redaction -------------------------------------------------------

    def redact(
        self,
        text: str,
        *,
        output: bool = True,
        layer: LayerName | str = LayerName.L5_OUTPUT_GUARD,
        taint: TaintMap | None = None,
    ) -> RedactionResult:
        """Mask secrets and PII. Returns rewritten text plus findings.

        Replacements are applied right-to-left so earlier offsets stay valid
        while the string is being rewritten underneath them.
        """
        rules = self.bundle.redaction.for_direction(output=output)
        if not text or not rules:
            return RedactionResult(text)

        hits: list[tuple[int, int, str, RedactionRule]] = []
        findings: list[Finding] = []
        drop = False

        for rule in rules:
            pattern = self._red_pattern(rule)
            try:
                matches = list(PolicyEngine._finditer(pattern, text))
            except TimeoutError:
                continue

            for match in matches[:MAX_HITS_PER_RULE]:
                matched = match.group(0)
                validator = VALIDATORS.get(rule.validator or "")
                if validator and not validator(matched):
                    continue

                start, end = match.span()
                if rule.mode is RedactionMode.DROP:
                    drop = True
                hits.append((start, end, rule.render(matched), rule))
                findings.append(
                    Finding(
                        layer=layer,
                        rule_id=rule.id,
                        message=rule.description or f"redacted {rule.id}",
                        severity=rule.severity,
                        family=AttackFamily.EXFILTRATION,
                        start=start,
                        end=end,
                        trust=taint.min_trust(start, end) if taint else TrustLevel.UNTRUSTED,
                        confidence=1.0,
                        # Zero: the value has already been removed from the
                        # text, so the response is safe. Recording it matters
                        # for audit and session risk; raising the score would
                        # block a response we just made harmless.
                        weight=0.0,
                        meta={"mode": rule.mode.value},
                    )
                )

        if not hits:
            return RedactionResult(text)

        # Resolve overlaps: keep the earliest start, longest match.
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        merged: list[tuple[int, int, str, RedactionRule]] = []
        for hit in hits:
            if merged and hit[0] < merged[-1][1]:
                continue
            merged.append(hit)

        buf = text
        for start, end, replacement, _rule in reversed(merged):
            buf = buf[:start] + replacement + buf[end:]

        return RedactionResult(text=buf, findings=findings, count=len(merged), drop=drop)

    # -- tool authorization ----------------------------------------------

    def evaluate_tool(
        self,
        name: str,
        args: dict[str, Any] | None = None,
        *,
        request_trust: TrustLevel = TrustLevel.USER,
        tainted_args: dict[str, bool] | None = None,
        request_tainted: bool = False,
        layer: LayerName | str = LayerName.L4_TOOL_GATE,
    ) -> ToolVerdict:
        """Decide whether one tool call may proceed.

        Four independent gates, cheapest and most decisive first:

          1. is there a rule at all (default deny)
          2. does the invoking context carry enough trust
          3. was the call *requested* by untrusted content
          4. do the arguments satisfy their constraints

        Gate 3 is the one that stops indirect injection. Detection can be
        argued with; provenance cannot. A fetched page may say "send an
        email" as many times as it likes and still never clear it.
        """
        args = args or {}
        tainted_args = tainted_args or {}
        findings: list[Finding] = []

        def _deny(rule_id: str, message: str, severity: Severity, decision: Decision) -> ToolVerdict:
            findings.append(
                Finding(
                    layer=layer,
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    family=AttackFamily.TOOL_ABUSE,
                    trust=request_trust,
                    source=f"tool:{name}",
                    confidence=1.0,
                    meta={"tool": name},
                )
            )
            return ToolVerdict(decision=decision, findings=findings, rule=rule_id)

        rule: ToolRule | None = self.bundle.tools.rule_for(name)
        if rule is None:
            if self.bundle.tools.default_effect == "deny":
                return _deny(
                    "tool.unlisted",
                    f"tool {name!r} has no policy rule and the default is deny",
                    Severity.HIGH,
                    Decision.BLOCK,
                )
            return ToolVerdict(decision=Decision.ALLOW, rule="tool.default_allow")

        if request_trust < rule.trust_floor:
            return _deny(
                "tool.insufficient_trust",
                (
                    f"{name} requires {rule.trust_floor.name.lower()} authority but the "
                    f"request carries only {request_trust.name.lower()}"
                ),
                rule.severity,
                rule.on_violation,
            )

        if rule.deny_if_tainted_request and request_tainted:
            return _deny(
                "tool.tainted_request",
                (
                    f"the decision to call {name} is traceable to untrusted content; "
                    f"{rule.side_effect} tools may not be driven by retrieved data"
                ),
                Severity.CRITICAL,
                rule.on_violation,
            )

        verdict = ToolVerdict(decision=Decision.ALLOW, findings=findings, rule=rule.name)

        for arg_name, value in args.items():
            arg_rule = rule.arg_rule(arg_name)
            is_tainted = bool(tainted_args.get(arg_name))
            text = value if isinstance(value, str) else str(value)

            # A named ArgRule is the authority for its own argument; the
            # rule-level flag is only the default for arguments nobody named.
            # send_email is the motivating case: quoting a fetched document
            # into a mail the user asked for is fine, but the recipient must
            # never be attacker-chosen.
            if is_tainted:
                tainted_ok = (
                    arg_rule.allow_tainted if arg_rule is not None else rule.allow_tainted_args
                )
                if not tainted_ok:
                    return _deny(
                        "tool.tainted_argument",
                        f"argument {arg_name!r} of {name} may not derive from untrusted content",
                        rule.severity,
                        rule.on_violation,
                    )
            if arg_rule is None:
                continue
            if arg_rule.max_length and len(text) > arg_rule.max_length:
                return _deny(
                    "tool.arg_too_long",
                    f"argument {arg_name!r} exceeds its {arg_rule.max_length} character limit",
                    Severity.MEDIUM,
                    Decision.BLOCK,
                )
            deny_pattern = arg_rule.compiled_deny()
            if deny_pattern is not None and deny_pattern.search(text, timeout=REGEX_TIMEOUT_S):
                return _deny(
                    "tool.arg_denied",
                    f"argument {arg_name!r} of {name} matches a denied pattern",
                    rule.severity,
                    rule.on_violation,
                )
            allow_pattern = arg_rule.compiled_allow()
            if allow_pattern is not None and not allow_pattern.search(text, timeout=REGEX_TIMEOUT_S):
                return _deny(
                    "tool.arg_not_allowed",
                    f"argument {arg_name!r} of {name} does not match its allowed form",
                    rule.severity,
                    rule.on_violation,
                )
            if arg_rule.allow_domains:
                for host in _URL_RE.findall(text):
                    if not _host_allowed(host, arg_rule.allow_domains):
                        return _deny(
                            "tool.domain_denied",
                            f"argument {arg_name!r} points at disallowed host {host!r}",
                            Severity.CRITICAL,
                            Decision.BLOCK,
                        )

        for arg_rule in rule.args:
            if arg_rule.required and arg_rule.name not in args and arg_rule.name != "*":
                return _deny(
                    "tool.arg_missing",
                    f"required argument {arg_rule.name!r} missing from {name}",
                    Severity.MEDIUM,
                    Decision.BLOCK,
                )

        if rule.require_confirmation:
            verdict.decision = Decision.CHALLENGE
            verdict.findings.append(
                Finding(
                    layer=layer,
                    rule_id="tool.confirmation_required",
                    message=f"{name} requires explicit confirmation before it runs",
                    severity=Severity.INFO,
                    family=AttackFamily.NONE,
                    trust=request_trust,
                    source=f"tool:{name}",
                    weight=0.0,
                    meta={"tool": name},
                )
            )
        return verdict


def _host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for entry in allowed:
        entry = entry.lower().lstrip("*.").rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False
