"""Detection + match/filter for INCLUDED.

Two layers:
  1. should_show()  — ffuf-style match/filter criteria (status/size/regex),
                      decides whether a response is shown at all (-v / fuzz mode).
  2. check()        — heuristics that confirm an actual read/execution
                      (known signatures, RCE marker, base64-encoded source).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from .config import Encoding, MatchFilter
from .http_client import Response


@dataclass
class Finding:
    confirmed: bool
    signal: str
    evidence: str
    payload: str
    status: int = 0
    length: int = 0
    # Full response body, set only after the post-scan verification re-fetch
    # (Engine._verify) — used for the CLI's "Reproduce" section so a real
    # `curl` isn't needed to see the whole thing.
    full_body: str | None = None
    # The concrete encoding variant that actually produced this finding
    # (relevant when --encode all fans out none/url/double per payload) —
    # verification and the "Reproduce" curl command must replay this exact
    # variant, not the config default, or they won't reproduce a finding
    # that only works double-encoded.
    encoding: Encoding = Encoding.NONE


# Marker injected into RCE payloads to unambiguously confirm execution.
RCE_MARKER = "INCLUDED_RCE_OK"

_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("/etc/passwd", re.compile(r"root:.*?:0:0:")),
    ("/etc/shadow", re.compile(r"root:[*!$]")),
    ("win.ini", re.compile(r"\[fonts\]|\[extensions\]", re.IGNORECASE)),
    ("boot.ini", re.compile(r"\[boot loader\]", re.IGNORECASE)),
    ("php source", re.compile(r"<\?php")),
    ("proc/environ", re.compile(r"PATH=|HTTP_USER_AGENT=")),
    ("php.ini", re.compile(r"allow_url_include|disable_functions")),
    ("RCE marker", re.compile(re.escape(RCE_MARKER))),
    ("command output (uid)", re.compile(r"uid=\d+\(")),
]


def should_show(resp: Response, mf: MatchFilter) -> bool:
    """Apply match/filter criteria. True = show this response."""
    # filters (hide if it matches)
    if mf.filter_codes and resp.status in mf.filter_codes:
        return False
    if mf.filter_size and resp.length in mf.filter_size:
        return False
    if mf.filter_regex and re.search(mf.filter_regex, resp.body):
        return False
    # matches (if set, MUST match)
    if mf.match_codes and resp.status not in mf.match_codes:
        return False
    if mf.match_size and resp.length not in mf.match_size:
        return False
    if mf.match_regex and not re.search(mf.match_regex, resp.body):
        return False
    return True


def check(resp: Response, mf: MatchFilter | None = None, *, expect_base64: bool = False) -> Finding:
    """Evaluate a single response for a confirmed finding."""
    if resp.error or not resp.body:
        return Finding(False, "", "", resp.payload, resp.status, resp.length)

    haystacks = [resp.body]
    if expect_base64:
        decoded = _try_b64(resp.body)
        if decoded:
            haystacks.append(decoded)

    for hay in haystacks:
        for name, pattern in _SIGNATURES:
            m = pattern.search(hay)
            if m:
                start = max(0, m.start() - 20)
                evidence = hay[start:m.end() + 40].replace("\n", "\\n")
                return Finding(True, name, evidence, resp.payload, resp.status, resp.length)

    # No known signature (e.g. arbitrary content like /flag.txt), but the
    # user explicitly set match/filter criteria (e.g. -fs <noise size>,
    # established the same way as in ffuf) and this response satisfies
    # them — treat it as a hit, same as ffuf showing everything past the
    # filtered-out noise. Error responses (4xx/5xx — e.g. 414 Request-URI
    # Too Long, when a payload is too long for the server) don't count on
    # their own — that's a failed request, not a signal — unless the user
    # explicitly asked to see that exact code via -mc.
    is_error_status = resp.status >= 400
    explicitly_wanted = mf.match_codes and resp.status in mf.match_codes if mf else False
    if (
        mf is not None and mf.has_criteria() and should_show(resp, mf)
        and (not is_error_status or explicitly_wanted)
    ):
        evidence = resp.body[:400].replace("\n", "\\n")
        return Finding(True, "match/filter", evidence, resp.payload, resp.status, resp.length)

    return Finding(False, "", "", resp.payload, resp.status, resp.length)


def _try_b64(body: str) -> str | None:
    for cand in sorted(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", body), key=len, reverse=True):
        try:
            return base64.b64decode(cand, validate=True).decode("utf-8", errors="replace")
        except Exception:
            continue
    return None
