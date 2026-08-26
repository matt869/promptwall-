"""Entropy-based secret detection.

Complements the pattern rules in ``redaction.yaml``. Those catch credentials
with a recognisable issuer prefix (``AKIA``, ``ghp_``, ``sk-``); this catches
the rest -- rotated formats, internal tokens, and anything issued by a vendor
nobody has written a rule for yet.

Entropy alone is a bad detector: hashes, UUIDs, minified JS and base64 images
are all high-entropy and all boring. The signal that actually works is
*entropy in a credential-shaped context* -- a high-entropy value sitting on
the right-hand side of something named like a secret.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .encoding import shannon_entropy

#: Names that make a following opaque value interesting.
_SECRET_NAME = (
    r"(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|credential|"
    r"auth|bearer|private[_-]?key|access[_-]?key|client[_-]?secret|"
    r"session[_-]?id|refresh[_-]?token|signing[_-]?key)"
)

_ASSIGNMENT_RE = re.compile(
    rf"(?i)\b{_SECRET_NAME}\b\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{{12,200}})[\"']?"
)

#: Things that look like secrets but are not, checked before reporting.
_BENIGN_RE = re.compile(
    r"(?i)^(?:"
    r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}"          # md5 / sha1 / sha256
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # uuid
    r"|(?:true|false|null|none|undefined|changeme|example|redacted|xxx+|\*+)"
    r"|(?:your|my|the)[_-]?(?:api[_-]?key|token|secret).*"
    r"|\$\{?[A-Z_][A-Z0-9_]*\}?"                        # ${ENV_VAR}
    r"|(?:process\.env|os\.environ).*"
    r")$"
)

#: Below this, a string is too predictable to be a modern credential.
MIN_ENTROPY = 3.2
MIN_LENGTH = 12


@dataclass(slots=True)
class SecretHit:
    start: int
    end: int
    entropy: float
    name: str
    value_preview: str
    kind: str = "assigned_secret"


def is_placeholder(value: str) -> bool:
    """Filter documentation and template values.

    Without this the detector fires on every README and .env.example, and a
    detector that cries wolf on documentation gets disabled within a week.
    """
    return bool(_BENIGN_RE.match(value.strip()))


def scan_secrets(text: str, *, min_entropy: float = MIN_ENTROPY) -> list[SecretHit]:
    """Find high-entropy values in credential-shaped assignments."""
    hits: list[SecretHit] = []
    if not text:
        return hits

    for match in _ASSIGNMENT_RE.finditer(text):
        value = match.group(1)
        if len(value) < MIN_LENGTH or is_placeholder(value):
            continue
        entropy = shannon_entropy(value)
        if entropy < min_entropy:
            continue
        name = match.group(0).split("=")[0].split(":")[0].strip()
        hits.append(
            SecretHit(
                start=match.start(1),
                end=match.end(1),
                entropy=round(entropy, 3),
                name=name[:60],
                value_preview=value[:4] + "..." + value[-2:] if len(value) > 8 else "...",
            )
        )
    return hits


def has_secret(text: str) -> bool:
    return bool(scan_secrets(text))
