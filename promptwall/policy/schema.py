"""Typed schema for policy files.

Policy lives in YAML so it can be reviewed, diffed and shipped without a code
release. This module is the contract: anything that fails validation here is
rejected at load time, because a silently-ignored security rule is worse than
a missing one.

Three packs, three files:
  signatures.yaml  what to look for
  tools.yaml       what a tool call must satisfy to be allowed
  redaction.yaml   what must never leave the building
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

import regex
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ..constants import AttackFamily, Decision, RedactionMode, Severity, TrustLevel
from ..exceptions import PolicyValidationError

#: Ceiling on how long a single regex may run against one input, in
#: milliseconds. Policy is data, and data can be hostile or merely sloppy;
#: a catastrophically backtracking pattern must not take the gateway down.
REGEX_TIMEOUT_S = 0.05


def _coerce_trust(value: Any) -> Any:
    """Let policy authors write ``third_party`` instead of ``10``.

    TrustLevel is an IntEnum so comparisons stay cheap in the hot path, but a
    YAML file full of bare integers is unreviewable, and a security rule that
    nobody can review is a security rule nobody can trust.
    """
    if isinstance(value, str):
        key = value.strip().lower()
        for level in TrustLevel:
            if level.name.lower() == key:
                return level
        valid = ", ".join(lvl.name.lower() for lvl in TrustLevel)
        raise ValueError(f"unknown trust level {value!r}; expected one of: {valid}")
    return value


#: A TrustLevel field that also accepts the level's name.
TrustField = Annotated[TrustLevel, BeforeValidator(_coerce_trust)]


class MatchTarget(BaseModel):
    """Which rendering of the text a signature is tested against."""

    model_config = ConfigDict(frozen=True)

    raw: bool = True
    normalized: bool = True
    decoded: bool = True


def compile_pattern(pattern: str, *, ignore_case: bool = True, rule_id: str = "") -> regex.Pattern:
    flags = regex.MULTILINE | regex.VERSION1
    if ignore_case:
        flags |= regex.IGNORECASE
    try:
        return regex.compile(pattern, flags)
    except regex.error as exc:
        raise PolicyValidationError(
            f"rule {rule_id or '<unnamed>'} has an invalid pattern: {exc}",
            rule_id=rule_id,
            pattern=pattern,
        ) from exc


class Signature(BaseModel):
    """One detection rule."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=80)
    description: str = ""
    family: AttackFamily = AttackFamily.INSTRUCTION_OVERRIDE
    severity: Severity = Severity.MEDIUM
    pattern: str = Field(min_length=1)
    ignore_case: bool = True
    enabled: bool = True

    #: Contribution to the risk score when this fires, 0..1. Defaults to the
    #: weight implied by severity.
    weight: float | None = Field(default=None, ge=0.0, le=1.0)

    targets: MatchTarget = Field(default_factory=MatchTarget)

    #: Only fire when the matched window's lowest trust is at or below this.
    #: A phrase like "ignore previous instructions" is a smell in a user turn
    #: but a near-certain attack inside a fetched web page, so many rules are
    #: scoped to untrusted provenance to keep false positives down.
    max_trust: TrustField = TrustLevel.SYSTEM

    #: Fire only if the pattern hits at least this many times.
    min_hits: int = Field(default=1, ge=1)

    #: Free-form labels used by the benchmark to slice results.
    tags: list[str] = Field(default_factory=list)

    @field_validator("pattern")
    @classmethod
    def _valid_regex(cls, v: str, info: Any) -> str:
        compile_pattern(v, rule_id=str((info.data or {}).get("id", "")))
        return v

    @field_validator("id")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not regex.fullmatch(r"[a-z0-9][a-z0-9_.\-]*", v):
            raise ValueError("id must be lowercase alphanumeric with . _ - separators")
        return v

    def compiled(self) -> regex.Pattern:
        return compile_pattern(self.pattern, ignore_case=self.ignore_case, rule_id=self.id)

    @property
    def effective_weight(self) -> float:
        from ..constants import SEVERITY_WEIGHT

        return self.weight if self.weight is not None else SEVERITY_WEIGHT[self.severity]


class SignaturePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "0"
    description: str = ""
    signatures: list[Signature] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> SignaturePack:
        seen: set[str] = set()
        for sig in self.signatures:
            if sig.id in seen:
                raise ValueError(f"duplicate signature id: {sig.id}")
            seen.add(sig.id)
        return self

    def enabled(self) -> list[Signature]:
        return [s for s in self.signatures if s.enabled]


class SideEffect(BaseModel):
    """Not a real model -- see SideEffectKind below. Kept for namespacing."""

    model_config = ConfigDict(frozen=True)


SideEffectKind = Literal["read", "write", "destructive", "external_comm"]

#: How much provenance authority each class of tool demands. Reading public
#: data on behalf of an untrusted document is usually fine; sending an email
#: because a fetched web page asked you to is the canonical disaster.
SIDE_EFFECT_FLOOR: dict[str, TrustLevel] = {
    "read": TrustLevel.THIRD_PARTY,
    "write": TrustLevel.USER,
    "external_comm": TrustLevel.USER,
    "destructive": TrustLevel.DEVELOPER,
}


class ArgRule(BaseModel):
    """Constraint on a single tool argument."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    #: If set, the value must match this to be allowed.
    allow_pattern: str | None = None
    #: If set, a match here denies the call outright.
    deny_pattern: str | None = None
    #: Hostnames this argument may point at. Applied to any URL found.
    allow_domains: list[str] = Field(default_factory=list)
    max_length: int | None = Field(default=None, gt=0)
    #: May this argument's value derive from untrusted text? Defaults False
    #: for anything a rule bothers to name.
    allow_tainted: bool = False
    required: bool = False

    @field_validator("allow_pattern", "deny_pattern")
    @classmethod
    def _valid(cls, v: str | None, info: Any) -> str | None:
        if v is not None:
            compile_pattern(v, rule_id=str((info.data or {}).get("name", "")))
        return v

    def compiled_allow(self) -> regex.Pattern | None:
        return compile_pattern(self.allow_pattern, rule_id=self.name) if self.allow_pattern else None

    def compiled_deny(self) -> regex.Pattern | None:
        return compile_pattern(self.deny_pattern, rule_id=self.name) if self.deny_pattern else None


class ToolRule(BaseModel):
    """Authorization policy for one tool (or a glob of tools)."""

    model_config = ConfigDict(extra="forbid")

    #: Exact tool name, or a glob such as ``db.*``.
    name: str = Field(min_length=1)
    description: str = ""
    side_effect: SideEffectKind = "read"
    enabled: bool = True

    #: Minimum trust the *invoking context* must have. Defaults from
    #: SIDE_EFFECT_FLOOR when omitted.
    min_trust: TrustField | None = None

    #: Deny when the model's decision to call this tool is traceable to
    #: untrusted content, regardless of argument contents. This is the single
    #: most effective control against indirect injection.
    deny_if_tainted_request: bool = True

    #: Allow arguments whose values derive from untrusted spans.
    allow_tainted_args: bool = True

    #: Escalate to a human instead of hard-blocking.
    require_confirmation: bool = False

    args: list[ArgRule] = Field(default_factory=list)
    on_violation: Decision = Decision.BLOCK
    severity: Severity = Severity.HIGH

    @model_validator(mode="after")
    def _apply_floor(self) -> ToolRule:
        if self.min_trust is None:
            object.__setattr__(self, "min_trust", SIDE_EFFECT_FLOOR[self.side_effect])
        return self

    @property
    def trust_floor(self) -> TrustLevel:
        return self.min_trust or SIDE_EFFECT_FLOOR[self.side_effect]

    def matches(self, tool_name: str) -> bool:
        if self.name == "*":
            return True
        if self.name.endswith(".*"):
            return tool_name.startswith(self.name[:-1])
        return self.name == tool_name

    def arg_rule(self, arg_name: str) -> ArgRule | None:
        for rule in self.args:
            if rule.name == arg_name or rule.name == "*":
                return rule
        return None


class ToolPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "0"
    description: str = ""
    #: What happens to a tool with no matching rule. ``deny`` is the safe
    #: default: a tool nobody wrote policy for is a tool nobody vetted.
    default_effect: Literal["allow", "deny"] = "deny"
    rules: list[ToolRule] = Field(default_factory=list)

    def rule_for(self, tool_name: str) -> ToolRule | None:
        """Most specific match wins: exact, then longest glob, then wildcard.

        Under ``default_effect: deny`` the ``*`` rule is deliberately NOT
        considered. Letting it match would mean every unlisted tool quietly
        picked up the wildcard policy instead of being denied, turning
        default-deny into default-allow-with-extra-steps. The wildcard exists
        so that a permissive deployment still gets taint checking rather than
        nothing at all.
        """
        candidates = [r for r in self.rules if r.enabled and r.matches(tool_name)]
        if self.default_effect == "deny":
            candidates = [r for r in candidates if r.name != "*"]
        if not candidates:
            return None
        return max(candidates, key=lambda r: (r.name != "*", not r.name.endswith(".*"), len(r.name)))


class RedactionRule(BaseModel):
    """Something that must not cross a boundary in the clear."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=80)
    description: str = ""
    pattern: str = Field(min_length=1)
    mode: RedactionMode = RedactionMode.MASK
    #: Replacement for MASK mode. ``{id}`` interpolates the rule id.
    replacement: str = "[REDACTED:{id}]"
    #: Characters kept at the tail in PARTIAL mode.
    keep_tail: int = Field(default=4, ge=0, le=32)
    severity: Severity = Severity.HIGH
    enabled: bool = True
    ignore_case: bool = False

    #: Which direction this applies to. Secrets usually matter on the way out;
    #: PII can matter in both directions.
    on_input: bool = False
    on_output: bool = True

    #: Optional checksum validator name, e.g. ``luhn`` for card numbers.
    validator: str | None = None

    @field_validator("pattern")
    @classmethod
    def _valid_regex(cls, v: str, info: Any) -> str:
        compile_pattern(v, rule_id=str((info.data or {}).get("id", "")))
        return v

    def compiled(self) -> regex.Pattern:
        return compile_pattern(self.pattern, ignore_case=self.ignore_case, rule_id=self.id)

    def render(self, matched: str) -> str:
        if self.mode is RedactionMode.PARTIAL and self.keep_tail:
            tail = matched[-self.keep_tail :] if len(matched) > self.keep_tail else ""
            return f"[REDACTED:{self.id}:...{tail}]"
        return self.replacement.format(id=self.id)


class RedactionPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "0"
    description: str = ""
    rules: list[RedactionRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> RedactionPack:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate redaction rule id: {rule.id}")
            seen.add(rule.id)
        return self

    def for_direction(self, *, output: bool) -> list[RedactionRule]:
        return [r for r in self.rules if r.enabled and (r.on_output if output else r.on_input)]


class PolicyBundle(BaseModel):
    """Everything the engine needs, loaded and validated together."""

    model_config = ConfigDict(extra="forbid")

    version: str = "0"
    signatures: SignaturePack = Field(default_factory=SignaturePack)
    tools: ToolPack = Field(default_factory=ToolPack)
    redaction: RedactionPack = Field(default_factory=RedactionPack)
    #: sha256 of the source files, so a verdict can name the exact policy that
    #: produced it and the admin replay endpoint can prove what was in force.
    digest: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "digest": self.digest,
            "signatures": len(self.signatures.enabled()),
            "signatures_total": len(self.signatures.signatures),
            "tool_rules": len(self.tools.rules),
            "tool_default": self.tools.default_effect,
            "redaction_rules": len(self.redaction.rules),
        }
