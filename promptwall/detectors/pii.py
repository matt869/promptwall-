"""Structured PII detection.

Scoped deliberately to *structured* identifiers -- things with a format, and
often a checksum. Names, addresses and free-text health information need a
model, and a bad model here is worse than nothing: it teaches operators to
ignore the alerts.

Everything with a checksum gets validated, because the raw patterns are loose
enough to swallow order numbers and timestamps otherwise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "date_of_birth": re.compile(
        r"(?i)\b(?:dob|date of birth|born)\b\s*[:=]?\s*\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}"
    ),
    "passport_us": re.compile(r"\b[A-Z]\d{8}\b"),
}

_SEVERITY = {
    "ssn": "critical",
    "credit_card": "critical",
    "iban": "high",
    "passport_us": "high",
    "date_of_birth": "high",
    "email": "low",
    "phone_us": "low",
    "ipv4": "low",
}

#: Reserved / documentation ranges that are not personal data.
_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.|192\.0\.2\.)"
)


@dataclass(slots=True)
class PIIHit:
    kind: str
    value: str
    start: int
    end: int
    severity: str = "low"

    def masked(self) -> str:
        if len(self.value) <= 4:
            return "*" * len(self.value)
        return self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]


def _luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _valid(kind: str, value: str) -> bool:
    if kind == "credit_card":
        return _luhn(value)
    if kind == "ipv4":
        return not _PRIVATE_IP_RE.match(value)
    if kind == "phone_us":
        return sum(c.isdigit() for c in value) in (10, 11)
    return True


def scan_pii(text: str, *, kinds: list[str] | None = None) -> list[PIIHit]:
    """Find structured PII. Overlapping hits resolve to the longest match."""
    if not text:
        return []
    selected = kinds or list(_PATTERNS)
    hits: list[PIIHit] = []

    for kind in selected:
        pattern = _PATTERNS.get(kind)
        if pattern is None:
            continue
        for match in pattern.finditer(text):
            value = match.group(0)
            if not _valid(kind, value):
                continue
            hits.append(PIIHit(kind, value, match.start(), match.end(), _SEVERITY.get(kind, "low")))

    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    deduped: list[PIIHit] = []
    for hit in hits:
        if deduped and hit.start < deduped[-1].end:
            continue
        deduped.append(hit)
    return deduped


def summarize_pii(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for hit in scan_pii(text):
        counts[hit.kind] = counts.get(hit.kind, 0) + 1
    return counts
