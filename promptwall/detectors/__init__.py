"""Detectors: focused analyzers the layers compose."""

from .encoding import (
    Decoded,
    NormalizeReport,
    decode_all,
    fold_confusables,
    normalize_text,
    shannon_entropy,
    strip_invisible,
)
from .pii import PIIHit, scan_pii, summarize_pii
from .secrets import SecretHit, has_secret, scan_secrets
from .sysprompt_leak import LeakReport, detect_leak, leaked
from .unsafe_markdown import MarkdownHit, has_exfil_risk, scan_markdown

__all__ = [
    "Decoded",
    "LeakReport",
    "MarkdownHit",
    "NormalizeReport",
    "PIIHit",
    "SecretHit",
    "decode_all",
    "detect_leak",
    "fold_confusables",
    "has_exfil_risk",
    "has_secret",
    "leaked",
    "normalize_text",
    "scan_markdown",
    "scan_pii",
    "scan_secrets",
    "shannon_entropy",
    "strip_invisible",
    "summarize_pii",
]
