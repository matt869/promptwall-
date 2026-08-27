"""A thin client for applications sitting behind PromptWall.

You do not need this. PromptWall speaks the provider's own wire format, so
pointing an existing OpenAI or Anthropic client at it works unchanged --
that is the whole design.

What this adds is the part the wire format has no room for:

  *Declaring provenance.* PromptWall infers trust from message roles, but the
  application usually knows better. `untrusted()` and `trusted()` attach the
  labels explicitly, and explicit labels always win over inference. This is
  the single highest-value thing an integrator can do.

  *Reading the verdict.* Decision, risk and request id come back as response
  headers on every call, including allows, which is what makes monitor mode
  useful.

  *Failing predictably.* A block raises `PromptWallBlocked` rather than
  surfacing as an opaque 403 from somewhere inside a provider SDK.

Dependencies: httpx only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterator

import httpx

DECISION_HEADER = "x-promptwall-decision"
RISK_HEADER = "x-promptwall-risk"
REQUEST_ID_HEADER = "x-promptwall-request-id"


class PromptWallError(Exception):
    """Base class for client-side errors."""


@dataclass
class Verdict:
    """What PromptWall concluded, lifted out of the response headers."""

    decision: str = "allow"
    risk: float = 0.0
    request_id: str = ""
    reason: str = ""
    families: list[str] = field(default_factory=list)
    advisory: bool = False

    @property
    def blocked(self) -> bool:
        return self.decision == "block" and not self.advisory

    @property
    def flagged(self) -> bool:
        """True whenever PromptWall objected, including in monitor mode.

        The one to watch during a monitor-mode rollout: it tells you what
        enforcement *would* have done, without anything being blocked yet.
        """
        return self.decision != "allow"

    @classmethod
    def from_headers(cls, headers: Any) -> Verdict:
        try:
            risk = float(headers.get(RISK_HEADER, 0.0) or 0.0)
        except (TypeError, ValueError):
            risk = 0.0
        return cls(
            decision=headers.get(DECISION_HEADER, "allow"),
            risk=risk,
            request_id=headers.get(REQUEST_ID_HEADER, ""),
        )


class PromptWallBlocked(PromptWallError):
    """Raised when PromptWall refuses a request or a response."""

    def __init__(self, verdict: Verdict, status_code: int = 403) -> None:
        super().__init__(verdict.reason or "blocked by PromptWall policy")
        self.verdict = verdict
        self.status_code = status_code


# --- provenance helpers ----------------------------------------------------


def untrusted(content: str, source: str = "") -> dict[str, Any]:
    """Label content as attacker-controllable.

    Use for anything you did not write: retrieved documents, tool output,
    fetched pages, uploaded files, other users' text. Getting this right
    matters more than any tuning you will do, because it is what lets the
    tool gate refuse a call on provenance rather than on a guess.
    """
    message: dict[str, Any] = {"role": "user", "content": content, "pw_trust": "untrusted"}
    if source:
        message["pw_source"] = source
    return message


def third_party(content: str, source: str = "") -> dict[str, Any]:
    """Retrieved data from a source you consider semi-reliable."""
    message: dict[str, Any] = {"role": "user", "content": content, "pw_trust": "third_party"}
    if source:
        message["pw_source"] = source
    return message


def trusted(content: str, role: str = "system") -> dict[str, Any]:
    """Label content as developer-authored.

    Only for text your code produced. Labelling user input as trusted
    disables the protection for that span, which is a decision to make
    deliberately and rarely.
    """
    return {"role": role, "content": content, "pw_trust": "developer"}


def tool_result(name: str, content: str, call_id: str = "") -> dict[str, Any]:
    """A tool result, labelled untrusted -- which is what tool output is."""
    message: dict[str, Any] = {"role": "tool", "name": name, "content": content}
    if call_id:
        message["tool_call_id"] = call_id
    return message


# --- the client ------------------------------------------------------------


class PromptWallClient:
    """Chat client that goes through a PromptWall gateway.

        client = PromptWallClient("http://localhost:8080", api_key="pw_...")
        reply, verdict = client.chat([
            trusted("You are a research assistant."),
            {"role": "user", "content": "Summarize this page."},
            tool_result("web_fetch", fetched_html),
        ])
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        model: str = "gpt-4o-mini",
        timeout: float = 60.0,
        raise_on_block: bool = True,
        session_id: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.raise_on_block = raise_on_block
        self.session_id = session_id
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers={
                "authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
        )

    def __enter__(self) -> PromptWallClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # -- requests --------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        session_id: str = "",
        **kwargs: Any,
    ) -> tuple[str, Verdict]:
        """Send a conversation. Returns (assistant_text, verdict)."""
        payload: dict[str, Any] = {
            "model": model or self.model,
            "messages": messages,
            **kwargs,
        }
        session = session_id or self.session_id
        if session:
            payload["pw_session_id"] = session

        response = self._client.post("/v1/chat/completions", json=payload)
        verdict = Verdict.from_headers(response.headers)

        if response.status_code == 403:
            verdict = _verdict_from_body(response, verdict)
            if self.raise_on_block:
                raise PromptWallBlocked(verdict, response.status_code)
            return "", verdict

        if response.status_code >= 400:
            raise PromptWallError(
                f"gateway returned HTTP {response.status_code}: {response.text[:300]}"
            )

        data = response.json()
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise PromptWallError("unexpected response shape from gateway") from exc
        return text, verdict

    def stream(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        session_id: str = "",
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream a reply.

        The gateway may terminate a stream mid-flight if the output guard
        trips, which arrives as an error frame rather than a truncated
        connection. That is raised as PromptWallBlocked, so a caller cannot
        mistake an intervention for a network fault.
        """
        payload: dict[str, Any] = {
            "model": model or self.model,
            "messages": messages,
            "stream": True,
            **kwargs,
        }
        session = session_id or self.session_id
        if session:
            payload["pw_session_id"] = session

        with self._client.stream("POST", "/v1/chat/completions", json=payload) as response:
            if response.status_code >= 400:
                response.read()
                verdict = Verdict.from_headers(response.headers)
                if response.status_code == 403:
                    raise PromptWallBlocked(_verdict_from_body(response, verdict))
                raise PromptWallError(f"gateway returned HTTP {response.status_code}")

            for line in response.iter_lines():
                if not line.startswith("data:"):
                    continue
                blob = line[5:].strip()
                if blob == "[DONE]":
                    return
                try:
                    event = json.loads(blob)
                except json.JSONDecodeError:
                    continue
                if "error" in event:
                    error = event["error"]
                    raise PromptWallBlocked(
                        Verdict(
                            decision="block",
                            reason=error.get("reason") or error.get("message", ""),
                        )
                    )
                for choice in event.get("choices", []):
                    piece = (choice.get("delta") or {}).get("content")
                    if piece:
                        yield piece

    # -- introspection ---------------------------------------------------

    def health(self) -> dict[str, Any]:
        return self._client.get("/healthz").json()

    def ready(self) -> tuple[bool, dict[str, Any]]:
        response = self._client.get("/readyz")
        return response.status_code == 200, response.json()


def _verdict_from_body(response: httpx.Response, fallback: Verdict) -> Verdict:
    """Enrich a header verdict with the block body, when there is one."""
    try:
        error = response.json().get("error", {})
        details = error.get("promptwall", {})
    except Exception:  # noqa: BLE001 - a non-JSON body is not worth failing over
        return fallback
    return Verdict(
        decision=details.get("decision", fallback.decision),
        risk=fallback.risk,
        request_id=details.get("request_id", fallback.request_id),
        reason=details.get("reason", error.get("message", "")),
        families=list(details.get("families", [])),
        advisory=bool(details.get("advisory", False)),
    )
