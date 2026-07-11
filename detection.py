"""Detekcja + match/filter dla INCLUDED.

Dwa poziomy:
  1. should_show()  — kryteria match/filter w stylu ffuf (status/size/regex),
                      decyduje czy odpowiedź w ogóle pokazać (tryb verbose/fuzz).
  2. check()        — heurystyki potwierdzające faktyczny odczyt/wykonanie
                      (sygnatury /etc/passwd, źródło PHP, marker RCE, base64).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from .config import MatchFilter
from .http_client import Response


@dataclass
class Finding:
    confirmed: bool
    signal: str
    evidence: str
    payload: str
    status: int = 0
    length: int = 0


# Marker, który wstrzykujemy w payloady RCE, by jednoznacznie potwierdzić wykonanie.
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
    """Zastosuj kryteria match/filter. True = pokaż odpowiedź."""
    # filtry (ukryj jeśli pasuje)
    if mf.filter_codes and resp.status in mf.filter_codes:
        return False
    if mf.filter_size and resp.length in mf.filter_size:
        return False
    if mf.filter_regex and re.search(mf.filter_regex, resp.body):
        return False
    # matche (jeśli ustawione, MUSI pasować)
    if mf.match_codes and resp.status not in mf.match_codes:
        return False
    if mf.match_size and resp.length not in mf.match_size:
        return False
    if mf.match_regex and not re.search(mf.match_regex, resp.body):
        return False
    return True


def check(resp: Response, *, expect_base64: bool = False) -> Finding:
    """Ocena pojedynczej odpowiedzi pod kątem potwierdzonego trafienia."""
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

    return Finding(False, "", "", resp.payload, resp.status, resp.length)


def _try_b64(body: str) -> str | None:
    for cand in sorted(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", body), key=len, reverse=True):
        try:
            return base64.b64decode(cand, validate=True).decode("utf-8", errors="replace")
        except Exception:
            continue
    return None
