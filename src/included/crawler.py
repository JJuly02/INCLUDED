"""Auto-discovery crawler for INCLUDED.

Crawls same-origin pages from a base URL and extracts candidate injection
points (query parameters and form fields) as ready-to-scan targets, so a
scan can start from a site root instead of a hand-picked INCLUDE URL. Pure
stdlib HTML parsing (html.parser) — no new dependency beyond aiohttp, which
the rest of the project already relies on exclusively.
"""
from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import aiohttp

from .config import INCLUDE, Config

_STATIC_EXTS = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".mp4",
    ".webp", ".avif",
)

# Attributes scanned for candidate (query-bearing) URLs. Deliberately wider
# than the "follow" set below — e.g. <img src="image.php?p=..."> is exactly
# the kind of endpoint LFI hides behind, even though we never crawl *into*
# an image response.
_CANDIDATE_ATTRS = {"a": "href", "img": "src", "script": "src", "link": "href", "iframe": "src"}
_SKIP_INPUT_TYPES = {"file", "submit", "button", "image", "reset"}


@dataclass(frozen=True)
class Candidate:
    """One discovered injection point, ready to drop into a Config as
    url=/method=/data= (param is only for display/reporting)."""
    url: str
    method: str
    data: str | None
    param: str
    source: str  # "query" | "form"

    def label(self) -> str:
        path = urlsplit(self.url).path or "/"
        return f"{self.method:<4} {path}  param={self.param}"


class _PageParser(HTMLParser):
    """One pass over an HTML page: same-page links to follow, query-bearing
    URLs as candidates, and <form> method/action/fields."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.candidate_urls: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            action = a.get("action") or self.base_url
            self._form = {
                "url": urljoin(self.base_url, action),
                "method": (a.get("method") or "GET").upper(),
                "fields": [],
            }
            self.forms.append(self._form)
            return
        if tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            itype = (a.get("type") or "text").lower()
            if name and itype not in _SKIP_INPUT_TYPES:
                self._form["fields"].append((name, a.get("value") or ""))
            return
        attr = _CANDIDATE_ATTRS.get(tag)
        if attr and a.get(attr):
            url = urljoin(self.base_url, a[attr])
            self.candidate_urls.append(url)
            if tag == "a":
                self.links.append(url)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def _same_origin(base: str, url: str) -> bool:
    b, u = urlsplit(base), urlsplit(url)
    return (b.scheme, b.netloc) == (u.scheme, u.netloc)


def _is_static(url: str) -> bool:
    return urlsplit(url).path.lower().endswith(_STATIC_EXTS)


def _strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _query_candidates(url: str) -> list[Candidate]:
    """One candidate per query parameter, that parameter's value swapped
    for INCLUDE, all others left as observed."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out = []
    for i, (k, _) in enumerate(pairs):
        query = "&".join(f"{k2}={INCLUDE if j == i else v2}" for j, (k2, v2) in enumerate(pairs))
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
        out.append(Candidate(url=target, method="GET", data=None, param=k, source="query"))
    return out


def _form_candidates(form: dict) -> list[Candidate]:
    """One candidate per form field, that field set to INCLUDE, the rest
    filled with their default value (or a harmless placeholder)."""
    fields = form["fields"]
    out = []
    for i, (name, _) in enumerate(fields):
        body = "&".join(
            f"{n}={INCLUDE if j == i else (v or 'test')}" for j, (n, v) in enumerate(fields)
        )
        if form["method"] == "GET":
            base = form["url"].split("?", 1)[0]
            out.append(Candidate(url=f"{base}?{body}", method="GET", data=None, param=name, source="form"))
        else:
            out.append(Candidate(url=form["url"], method="POST", data=body, param=name, source="form"))
    return out


async def crawl(cfg: Config, start_url: str, *, max_depth: int, max_pages: int,
                 verbose: bool = False) -> list[Candidate]:
    """BFS same-origin crawl from start_url, returning deduped candidates.

    Only follows <a href> links (real pages); every href/src/action seen
    anywhere is still checked for a candidate query string, since a lot of
    real injection points (e.g. an <img src="image.php?p=...">) are never
    themselves "pages" to crawl into.
    """
    visited: set[str] = set()
    candidates: dict[tuple[str, str, str], Candidate] = {}
    queue: list[tuple[str, int]] = [(start_url, 0)]

    connector = aiohttp.TCPConnector(ssl=cfg.verify_tls)
    async with aiohttp.ClientSession(
        connector=connector, headers=cfg.headers, cookies=cfg.cookies,
        timeout=aiohttp.ClientTimeout(total=cfg.timeout),
    ) as session:

        def _add(cands: list[Candidate]) -> None:
            for c in cands:
                key = (c.method, c.url.split("?", 1)[0], c.param)
                candidates.setdefault(key, c)

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            norm = _strip_fragment(url)
            if norm in visited:
                continue
            visited.add(norm)

            try:
                async with session.get(url, proxy=cfg.proxy, allow_redirects=True) as resp:
                    status = resp.status
                    ctype = resp.headers.get("Content-Type", "")
                    final_url = str(resp.url)
                    body = await resp.text(errors="replace") if "html" in ctype else ""
            except Exception as exc:
                if verbose:
                    print(f"    [crawl] {url} -> error: {exc}")
                continue

            if verbose:
                print(f"    [crawl] [{status}] {url}")

            _add(_query_candidates(final_url))
            if not body:
                continue

            parser = _PageParser(final_url)
            try:
                parser.feed(body)
            except Exception:
                continue

            for cu in parser.candidate_urls:
                if _same_origin(start_url, cu) and not _is_static(cu):
                    _add(_query_candidates(cu))

            for form in parser.forms:
                if _same_origin(start_url, form["url"]):
                    _add(_form_candidates(form))

            if depth < max_depth:
                for link in parser.links:
                    if (_same_origin(start_url, link) and not _is_static(link)
                            and _strip_fragment(link) not in visited):
                        queue.append((link, depth + 1))

    return sorted(candidates.values(), key=lambda c: (c.url, c.param))
