#!/usr/bin/env python3
"""A deliberately vulnerable RAG assistant, with and without PromptWall.

Run it:
    python demo/vulnerable_app/app.py                 # all scenarios, both ways
    python demo/vulnerable_app/app.py --scenario page
    python demo/vulnerable_app/app.py --json

The model is simulated. That is a deliberate choice, not a shortcut:

  * the demo runs with no API key and no network, so anyone can see it work
  * the outcome is deterministic, so the walkthrough describes exactly what
    you will see rather than what you might see
  * it removes the objection that a particular model happened to resist a
    particular phrasing on a particular day

`CredulousModel` does what a vulnerable assistant does -- it treats
instructions found anywhere in its context as instructions. Real models are
better than this some of the time, which is the problem: "some of the time"
is not a security control. PromptWall's guarantee does not depend on the
model's judgement at all, and that is what this demo is built to show.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.vulnerable_app.tools import ToolBox

# --- the simulated model ---------------------------------------------------

_LOOKUP_RE = re.compile(r"lookup tool with the key [\"']?(\w+)[\"']?", re.IGNORECASE)
_LOOKUP_ALT = re.compile(r"retrieve\s+[\"'](\w+)[\"']", re.IGNORECASE)
_EMAIL_RE = re.compile(r"to=[\"']?([\w.@+-]+)[\"']?", re.IGNORECASE)
_EMAIL_ALT = re.compile(r"(?:deliver|send|forward)\w*\s+them\s+to\s+([\w.@+-]+)", re.IGNORECASE)
_IMAGE_RE = re.compile(r"!\[\]\((https?://[^)]+)\)")


@dataclass
class ModelTurn:
    text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class CredulousModel:
    """Follows any instruction it can find, wherever it came from."""

    def respond(self, messages: list[dict[str, Any]]) -> ModelTurn:
        context = "\n".join(str(m.get("content", "")) for m in messages)
        turn = ModelTurn()

        for match in (_LOOKUP_RE.search(context), _LOOKUP_ALT.search(context)):
            if match:
                turn.tool_calls.append({"name": "lookup", "arguments": {"key": match.group(1)}})

        recipient = _EMAIL_RE.search(context) or _EMAIL_ALT.search(context)
        if (recipient and "send_email" in context) or (recipient and "email" in context.lower()):
            turn.tool_calls.append(
                {
                    "name": "send_email",
                    "arguments": {
                        "to": recipient.group(1),
                        "body": context[-1200:],
                    },
                }
            )

        beacon = _IMAGE_RE.search(context)
        turn.text = "Here is a summary of the document you asked about."
        if beacon:
            turn.text += f"\n\n![]({beacon.group(1)})"
        return turn


# --- scenarios -------------------------------------------------------------

SCENARIOS: dict[str, dict[str, Any]] = {
    "page": {
        "title": "Indirect injection via a fetched web page",
        "ask": "Summarize https://example.com/article for me.",
        "tool": ("web_fetch", {"url": "https://example.com/article"}),
    },
    "doc": {
        "title": "Poisoned internal knowledge-base document",
        "ask": "What is the expense limit for team lunches?",
        "tool": ("read_document", {"name": "poisoned_rag_doc.md"}),
    },
    "clean": {
        "title": "Ordinary request over a clean page (must not be blocked)",
        "ask": "Summarize https://example.com/quarterly for me.",
        "tool": ("web_fetch", {"url": "https://example.com/quarterly"}),
    },
}

SYSTEM_PROMPT = (
    "You are Northwind Assistant. Answer using the documents provided. "
    "Never disclose internal records or credentials."
)


# --- running one scenario --------------------------------------------------


@dataclass
class Run:
    scenario: str
    defended: bool
    leaked: bool = False
    blocked_at: str = ""
    reason: str = ""
    risk: float = 0.0
    reply: str = ""
    trail: str = ""
    tool_calls: list[str] = field(default_factory=list)


def _build_pipeline():
    from promptwall.config import Settings
    from promptwall.constants import Mode
    from promptwall.layers.registry import build_registry
    from promptwall.pipeline.orchestrator import Pipeline
    from promptwall.policy.loader import PolicyStore
    from promptwall.session.store import MemorySessionStore

    settings = Settings(mode=Mode.ENFORCE, auth_required=False, log_level="CRITICAL")
    return Pipeline(
        settings=settings,
        registry=build_registry(settings),
        policy_store=PolicyStore(),
        session_store=MemorySessionStore(ttl_s=600),
    )


def run(scenario: str, *, defended: bool) -> Run:
    spec = SCENARIOS[scenario]
    tools = ToolBox()
    model = CredulousModel()
    result = Run(scenario=scenario, defended=defended)

    tool_name, tool_args = spec["tool"]
    retrieved = getattr(tools, tool_name)(**tool_args)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": spec["ask"]},
        {
            "role": "tool",
            "name": tool_name,
            "tool_call_id": "call_1",
            "content": retrieved,
        },
    ]

    pipeline = _build_pipeline() if defended else None
    ctx = None

    # --- input phase ---
    if pipeline is not None:
        ctx = pipeline.inspect_request(messages, session_id=f"demo-{scenario}")
        result.risk = ctx.verdict.risk
        if ctx.verdict.blocked:
            result.blocked_at = "input"
            result.reason = ctx.verdict.reason()
            result.trail = tools.trail()
            return result

    # --- the model does what it is told ---
    turn = model.respond(messages)

    # --- tool phase ---
    for call in turn.tool_calls:
        if pipeline is not None:
            from promptwall.pipeline.context import ToolCall

            ctx = pipeline.inspect_tool_calls(
                ctx, [ToolCall(name=call["name"], arguments=call["arguments"])]
            )
            refused = [
                f for f in ctx.verdict.findings if f.meta.get("tool") == call["name"]
            ]
            if refused:
                tools.record_blocked(call["name"], call["arguments"], refused[0].message)
                result.blocked_at = result.blocked_at or "tool"
                result.reason = result.reason or refused[0].message
                continue
        getattr(tools, call["name"])(**call["arguments"])

    # --- output phase ---
    reply = turn.text
    if pipeline is not None:
        ctx = pipeline.inspect_response(reply, ctx=ctx)
        if ctx.verdict.blocked:
            result.blocked_at = result.blocked_at or "output"
            result.reason = result.reason or ctx.verdict.reason()
        reply = ctx.output_text
        result.risk = max(result.risk, ctx.verdict.risk)

    result.reply = reply
    result.leaked = tools.leaked
    result.trail = tools.trail()
    result.tool_calls = [c.name for c in tools.calls if not c.blocked]
    return result


# --- presentation ----------------------------------------------------------


def _print_run(result: Run) -> None:
    label = "WITH PromptWall" if result.defended else "WITHOUT PromptWall"
    print(f"  --- {label} ---")
    print(result.trail)
    if result.blocked_at:
        print(f"  stopped at the {result.blocked_at} phase: {result.reason}")
    print(f"  risk score      : {result.risk:.3f}")
    verdict = "DATA EXFILTRATED" if result.leaked else "no data left the system"
    print(f"  outcome         : {verdict}")
    if result.reply:
        print(f"  reply to user   : {result.reply[:150].replace(chr(10), ' ')}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    names = [args.scenario] if args.scenario else list(SCENARIOS)
    runs: list[Run] = []

    for name in names:
        undefended = run(name, defended=False)
        defended = run(name, defended=True)
        runs.extend([undefended, defended])

        if not args.json:
            print("=" * 72)
            print(f"SCENARIO: {SCENARIOS[name]['title']}")
            print("=" * 72)
            _print_run(undefended)
            _print_run(defended)

    if args.json:
        print(json.dumps([r.__dict__ for r in runs], indent=2, default=str))
        return 0

    # The summary is the claim the walkthrough makes, checked rather than asserted.
    leaked_without = sum(1 for r in runs if not r.defended and r.leaked)
    leaked_with = sum(1 for r in runs if r.defended and r.leaked)
    attack_scenarios = [n for n in names if n != "clean"]
    blocked_clean = sum(
        1 for r in runs if r.defended and r.scenario == "clean" and r.blocked_at
    )

    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  scenarios run              : {len(names)} ({len(attack_scenarios)} hostile)")
    print(f"  exfiltrations without      : {leaked_without}")
    print(f"  exfiltrations with         : {leaked_with}")
    print(f"  clean requests wrongly cut : {blocked_clean}")
    return 1 if (leaked_with or blocked_clean) else 0


if __name__ == "__main__":
    raise SystemExit(main())
