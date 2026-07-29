"""Auto-discovery crawler for INCLUDED.

Crawls same-origin pages from a base URL and extracts candidate injection
points (query parameters and form fields) as ready-to-scan targets, so a
scan can start from a site root instead of a hand-picked INCLUDE URL. Pure
stdlib HTML parsing (html.parser) — no new dependency beyond aiohttp, which
the rest of the project already relies on exclusively.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
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
_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset"}

_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"


def _load_params_wordlist(path: str | None) -> list[str]:
    """Hidden-param names to fuzz on every crawled page. --params-wordlist
    overrides the small bundled default (see wordlists/params.txt for why
    it's kept short: it's a multiplier on total crawl requests)."""
    target = Path(path) if path else _WORDLIST_DIR / "params.txt"
    try:
        with target.open(encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


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


@dataclass(frozen=True)
class UploadForm:
    """A form with a file input — a candidate target for the upload ->
    guess-filename -> trigger-RCE chain (chain.py), kept separate from
    Candidate since "upload a file here" isn't "inject INCLUDE here"."""
    url: str
    method: str
    file_field: str
    other_fields: list[tuple[str, str]] = field(default_factory=list)


class _PageParser(HTMLParser):
    """One pass over an HTML page: same-page links to follow, query-bearing
    URLs as candidates, and <form> method/action/fields (including which
    form has a file input, tracked separately for the upload chain)."""

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
                "file_field": None,
            }
            self.forms.append(self._form)
            return
        if tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            itype = (a.get("type") or "text").lower()
            if not name or itype in _SKIP_INPUT_TYPES:
                return
            if itype == "file":
                if self._form["file_field"] is None:
                    self._form["file_field"] = name
                return
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
    """One candidate per (non-file) form field, that field set to INCLUDE,
    the rest filled with their default value (or a harmless placeholder)."""
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


def _param_fuzz_candidates(url: str, param_names: list[str]) -> list[Candidate]:
    """One candidate per wordlist param name NOT already present on this
    page's URL — finds injection points that exist in server code but
    were never linked anywhere (e.g. a `region` param only visible by
    reading source, not by crawling)."""
    parts = urlsplit(url)
    existing = {k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}
    out = []
    for name in param_names:
        if name in existing:
            continue
        sep = "&" if parts.query else ""
        query = f"{parts.query}{sep}{name}={INCLUDE}"
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
        out.append(Candidate(url=target, method="GET", data=None, param=name, source="param-fuzz"))
    return out


async def crawl(cfg: Config, start_url: str, *, max_depth: int, max_pages: int,
                 verbose: bool = False, fuzz_params: bool = True,
                 params_wordlist: str | None = None,
                 ) -> tuple[list[Candidate], list[UploadForm]]:
    """BFS same-origin crawl from start_url, returning deduped candidates
    plus any discovered file-upload forms.

    Only follows <a href> links (real pages); every href/src/action seen
    anywhere is still checked for a candidate query string, since a lot of
    real injection points (e.g. an <img src="image.php?p=...">) are never
    themselves "pages" to crawl into.
    """
    visited: set[str] = set()
    candidates: dict[tuple[str, str, str], Candidate] = {}
    upload_forms: dict[tuple[str, str, str], UploadForm] = {}
    queue: list[tuple[str, int]] = [(start_url, 0)]
    param_names = _load_params_wordlist(params_wordlist) if fuzz_params else []

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
            if param_names:
                _add(_param_fuzz_candidates(final_url, param_names))
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
                if not _same_origin(start_url, form["url"]):
                    continue
                _add(_form_candidates(form))
                if form["file_field"]:
                    uf = UploadForm(
                        url=form["url"], method=form["method"] or "POST",
                        file_field=form["file_field"],
                        other_fields=[(n, v or "test") for n, v in form["fields"]],
                    )
                    upload_forms.setdefault((uf.url, uf.method, uf.file_field), uf)

            if depth < max_depth:
                for link in parser.links:
                    if (_same_origin(start_url, link) and not _is_static(link)
                            and _strip_fragment(link) not in visited):
                        queue.append((link, depth + 1))

    return sorted(candidates.values(), key=lambda c: (c.url, c.param)), list(upload_forms.values())
