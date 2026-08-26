"""Append-only audit log.

Separate from the application log on purpose. This is the record an incident
review reads months later, so it has different requirements: every entry is
self-contained, carries the exact policy digest that produced the decision,
and can be shown not to have been edited after the fact.

Tamper evidence is a hash chain: each record includes the HMAC of the
previous one. That does not stop an attacker with write access from
truncating the file, but it does stop them from quietly altering an entry in
the middle of it, which is the realistic case when the goal is hiding a
single request.

Content logging is off by default. A file containing every prompt users sent
is exactly the thing an attacker wants, and turning it on should be a
deliberate, documented decision.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from ..constants import AUDIT_SCHEMA_VERSION

GENESIS = "0" * 64


class AuditLog:
    """Line-delimited JSON, one record per evaluated phase."""

    def __init__(
        self,
        path: str | Path,
        *,
        enabled: bool = True,
        store_content: bool = False,
        hmac_key: str = "",
        max_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self.store_content = store_content
        self._key = hmac_key.encode() if hmac_key else b""
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._written = 0
        self._errors = 0
        if self.enabled:
            self._prepare()

    def _prepare(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                self._prev = self._last_hash()
        except OSError:
            # An unwritable audit path must not prevent the gateway from
            # starting; it degrades to disabled and says so.
            self.enabled = False

    def _last_hash(self) -> str:
        last = ""
        try:
            with self.path.open("rb") as handle:
                for raw in handle:
                    if raw.strip():
                        last = raw.decode("utf-8", errors="replace")
        except OSError:
            return GENESIS
        if not last:
            return GENESIS
        try:
            return json.loads(last).get("hash", GENESIS)
        except json.JSONDecodeError:
            return GENESIS

    # -- writing ---------------------------------------------------------

    def record(self, ctx: Any, extra: dict[str, Any] | None = None) -> str | None:
        """Append one verdict. Returns the record hash, or None if disabled."""
        if not self.enabled:
            return None

        verdict = ctx.verdict
        entry: dict[str, Any] = {
            "v": AUDIT_SCHEMA_VERSION,
            "ts": round(time.time(), 3),
            **verdict.to_audit_dict(include_content=self.store_content),
            "provenance": {
                "lowest_trust": ctx.lowest_trust.name.lower(),
                "has_untrusted": ctx.has_untrusted,
                "messages": len(ctx.messages),
                "sources": ctx.taint.sources()[:20],
            },
            "tool_calls": [call.to_dict() for call in ctx.tool_calls],
        }
        if self.store_content:
            entry["content"] = {
                "raw": ctx.raw_text[:8000],
                "normalized": ctx.normalized[:8000],
                "output": ctx.output_text[:8000],
            }
        if extra:
            entry["extra"] = extra
        return self._append(entry)

    def _append(self, entry: dict[str, Any]) -> str | None:
        with self._lock:
            entry["prev"] = self._prev
            body = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
            entry["hash"] = self._digest(body)
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
            try:
                self._rotate_if_needed()
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                self._errors += 1
                return None
            self._prev = entry["hash"]
            self._written += 1
            return entry["hash"]

    def _digest(self, body: str) -> str:
        if self._key:
            return hmac.new(self._key, body.encode("utf-8"), hashlib.sha256).hexdigest()
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size >= self._max_bytes:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                self.path.rename(self.path.with_suffix(f".{stamp}{self.path.suffix}"))
        except OSError:
            pass

    # -- verification ----------------------------------------------------

    def verify(self) -> dict[str, Any]:
        """Walk the chain and report the first break, if any."""
        if not self.path.exists():
            return {"ok": True, "records": 0, "note": "no audit file"}

        prev = GENESIS
        count = 0
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for lineno, raw in enumerate(handle, 1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        return {"ok": False, "records": count, "broken_at": lineno,
                                "reason": "malformed JSON"}
                    if entry.get("prev") != prev:
                        return {"ok": False, "records": count, "broken_at": lineno,
                                "reason": "chain link mismatch"}
                    recorded = entry.pop("hash", "")
                    body = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
                    if self._digest(body) != recorded:
                        return {"ok": False, "records": count, "broken_at": lineno,
                                "reason": "hash mismatch"}
                    prev = recorded
                    count += 1
        except OSError as exc:
            return {"ok": False, "records": count, "reason": str(exc)}
        return {"ok": True, "records": count, "head": prev}

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "path": str(self.path),
            "store_content": self.store_content,
            "hmac": bool(self._key),
            "written": self._written,
            "errors": self._errors,
            "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }


_audit: AuditLog | None = None


def get_audit(settings=None) -> AuditLog:
    global _audit
    if _audit is None:
        if settings is None:
            from ..config import get_settings  # noqa: PLC0415

            settings = get_settings()
        cfg = settings.telemetry
        _audit = AuditLog(
            cfg.audit_path,
            enabled=cfg.audit_enabled,
            store_content=cfg.audit_store_content,
            hmac_key=cfg.audit_hmac_key,
        )
    return _audit


def reset_audit() -> None:
    global _audit
    _audit = None
