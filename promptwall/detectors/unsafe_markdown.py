"""Markdown and HTML constructs that exfiltrate data without a click.

The canonical zero-click LLM exfiltration: an injection persuades the model
to emit an image whose URL embeds the conversation. The user never clicks
anything -- the renderer fetches it, and the data is gone.

Anything that causes an automatic outbound request is treated the same way:
images, HTML tags with src/href, CSS url(), and form actions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

#: ![alt](url) -- auto-fetched by every markdown renderer.
_MD_IMAGE_RE = re.compile(r"!\[(?P<alt>[^\]]*)\]\(\s*(?P<url>[^)\s]+)[^)]*\)")
_MD_LINK_RE = re.compile(r"(?<!!)\[(?P<text>[^\]]*)\]\(\s*(?P<url>[^)\s]+)[^)]*\)")
_HTML_SRC_RE = re.compile(
    r"(?i)<\s*(?P<tag>img|script|iframe|embed|video|audio|source|object|link)\b[^>]*?"
    r"\b(?:src|href|data)\s*=\s*[\"']?(?P<url>[^\"'>\s]+)"
)
_CSS_URL_RE = re.compile(r"(?i)url\(\s*[\"']?(?P<url>[^)\"']+)")
_FORM_RE = re.compile(r"(?i)<\s*form\b[^>]*\baction\s*=\s*[\"']?(?P<url>[^\"'>\s]+)")

#: Schemes that should never appear in model output.
_DANGEROUS_SCHEMES = {"javascript", "vbscript", "data", "file", "gopher"}


@dataclass(slots=True)
class MarkdownHit:
    kind: str
    url: str
    start: int
    end: int
    reason: str
    auto_fetch: bool = True

    @property
    def host(self) -> str:
        try:
            return (urlparse(self.url).hostname or "").lower()
        except ValueError:
            return ""


#: A query value that looks like encoded data rather than a parameter.
_ENCODED_VALUE_RE = re.compile(
    r"^(?:[A-Za-z0-9+/_-]{20,}={0,2}|[0-9a-fA-F]{20,}|(?:%[0-9A-Fa-f]{2}){6,}.*)$"
)


def _query_payload_len(url: str) -> int:
    """Length of query/fragment data -- the exfiltration channel itself."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return 0
    return len(parsed.query) + len(parsed.fragment)


def _encoded_payload(url: str) -> str:
    """Return the first query/fragment value that looks like smuggled data.

    Raw length is a poor discriminator on its own: signed CDN URLs are long
    and legitimate, while a leaked API key rides in a short one. What
    separates them is *shape* -- an exfiltrated value is encoded, so it is a
    long unbroken run of base64/hex/percent-escapes rather than the short
    words and numbers real parameters carry.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    for blob in (parsed.query, parsed.fragment):
        if not blob:
            continue
        for pair in re.split(r"[&;]", blob):
            _, _, value = pair.partition("=")
            candidate = value or pair
            if len(candidate) >= 20 and _ENCODED_VALUE_RE.match(candidate):
                return candidate
    return ""


def scan_markdown(
    text: str,
    *,
    allowed_hosts: list[str] | None = None,
    max_query_len: int = 48,
) -> list[MarkdownHit]:
    """Find constructs that could leak data out of a rendered response.

    ``max_query_len`` is the interesting knob. A tracking pixel and a
    legitimate CDN image look identical apart from how much data rides along
    in the query string, so length is the discriminator rather than presence.
    """
    hits: list[MarkdownHit] = []
    if not text:
        return hits
    allow = {h.lower().lstrip("*.") for h in (allowed_hosts or [])}

    def _check(kind: str, url: str, start: int, end: int, auto: bool) -> None:
        scheme = ""
        try:
            scheme = (urlparse(url).scheme or "").lower()
        except ValueError:
            pass
        if scheme in _DANGEROUS_SCHEMES:
            hits.append(MarkdownHit(kind, url, start, end, f"{scheme}: scheme", auto))
            return
        if auto:
            encoded = _encoded_payload(url)
            if encoded:
                hits.append(
                    MarkdownHit(
                        kind, url, start, end,
                        f"encoded {len(encoded)}-char payload in query",
                        auto,
                    )
                )
                return
            payload = _query_payload_len(url)
            if payload > max_query_len:
                hits.append(
                    MarkdownHit(kind, url, start, end, f"{payload} chars of query payload", auto)
                )
                return
        if auto and allow:
            host = (urlparse(url).hostname or "").lower() if url else ""
            if host and not any(host == a or host.endswith("." + a) for a in allow):
                hits.append(MarkdownHit(kind, url, start, end, f"unlisted host {host}", auto))

    for match in _MD_IMAGE_RE.finditer(text):
        _check("markdown_image", match.group("url"), *match.span(), True)
    for match in _HTML_SRC_RE.finditer(text):
        tag = match.group("tag").lower()
        _check(f"html_{tag}", match.group("url"), *match.span(), tag != "a")
    for match in _CSS_URL_RE.finditer(text):
        _check("css_url", match.group("url"), *match.span(), True)
    for match in _FORM_RE.finditer(text):
        _check("form_action", match.group("url"), *match.span(), False)
    for match in _MD_LINK_RE.finditer(text):
        _check("markdown_link", match.group("url"), *match.span(), False)

    return hits


def has_exfil_risk(text: str, **kwargs) -> bool:
    return any(hit.auto_fetch for hit in scan_markdown(text, **kwargs))
