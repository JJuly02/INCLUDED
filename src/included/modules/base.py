"""Technique module contract for INCLUDED.

A new technique = a BaseModule subclass + a registry entry. The engine
doesn't know the details — it asks for payloads, sends them, evaluates.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from ..config import Config, Encoding, OSHint
from ..detection import Finding, check, should_show
from ..http_client import HttpClient, Response

# Concrete variants tried per payload when --encode all (the default) is set.
_ALL_ENCODINGS = (Encoding.NONE, Encoding.URL, Encoding.DOUBLE_URL)

_WORDLIST_DIR = Path(__file__).resolve().parent.parent / "wordlists"

# Fallback targets in case wordlists/*.txt is missing from a given install
# (e.g. a package without data files) — DEFAULT_TARGETS normally loads
# from those files.
_FALLBACK_TARGETS = {
    OSHint.LINUX: ["/etc/passwd", "/etc/shadow", "/etc/hosts",
                   "/proc/self/environ", "/var/www/html/config.php"],
    OSHint.WINDOWS: ["C:/Windows/win.ini", "C:/boot.ini",
                     "C:/Windows/System32/drivers/etc/hosts"],
}


def _load_wordlist(name: str, os_hint: OSHint) -> list[str]:
    try:
        with (_WORDLIST_DIR / name).open(encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        return lines or _FALLBACK_TARGETS[os_hint]
    except OSError:
        return _FALLBACK_TARGETS[os_hint]


# Default targets per OS (when the user didn't pass -f/--file or -W/--wordlist).
# Loaded from wordlists/linux.txt and wordlists/windows.txt.
DEFAULT_TARGETS = {
    OSHint.LINUX: _load_wordlist("linux.txt", OSHint.LINUX),
    OSHint.WINDOWS: _load_wordlist("windows.txt", OSHint.WINDOWS),
}


class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    expect_base64: bool = False
    # Whether the post-scan verification pass (Engine._verify) can safely
    # replay a finding with a plain client.send(payload). False for modules
    # whose run() does something payloads() can't capture on its own (a
    # POST body, extra headers, a hosted shell that's gone once run()
    # returns) — see InputWrapperModule, LogPoisonModule, RFIModule.
    verifiable: bool = True

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def targets(self) -> list[str]:
        """List of target files. Priority: -f > -W > OS defaults."""
        if self.cfg.target_file:
            return [self.cfg.target_file]
        if self.cfg.wordlist:
            try:
                with open(self.cfg.wordlist, encoding="utf-8", errors="replace") as fh:
                    return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
            except OSError:
                return []
        if self.cfg.os_hint == OSHint.WINDOWS:
            return DEFAULT_TARGETS[OSHint.WINDOWS]
        if self.cfg.os_hint == OSHint.LINUX:
            return DEFAULT_TARGETS[OSHint.LINUX]
        return DEFAULT_TARGETS[OSHint.LINUX] + DEFAULT_TARGETS[OSHint.WINDOWS]

    @abstractmethod
    def payloads(self) -> Iterator[str]:
        raise NotImplementedError

    def evaluate(self, resp: Response) -> Finding:
        return check(resp, self.cfg.mf, expect_base64=self.expect_base64)

    def dedup(self, findings: list[Finding]) -> list[Finding]:
        """Keep only the first confirmation per (signal, evidence) — the
        same file hit by different payload variants (depth/encoding/bypass)
        produces identical evidence, so that's enough to key "the same file".
        Disabled by --all-hits.
        """
        if self.cfg.all_hits:
            return findings
        seen: set[tuple[str, str]] = set()
        out: list[Finding] = []
        for f in findings:
            key = (f.signal, f.evidence)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    async def _send_eval(self, client: HttpClient, payload: str) -> Finding:
        """Send `payload`, trying every encoding variant when --encode all
        is set (the default), stopping at the first confirmed one. Without
        this, "all" was a silent no-op identical to "none" — a real
        vulnerability that's only reachable double-encoded (e.g. a
        blacklist bypassed by double-URL-encoding `../`) would never be
        found even though the payload shape was right.
        """
        encodings = _ALL_ENCODINGS if self.cfg.encoding == Encoding.ALL else (self.cfg.encoding,)
        last = Finding(False, "", "", payload)
        for enc in encodings:
            resp = await client.send(payload, encoding=enc)
            if self.cfg.verbose and should_show(resp, self.cfg.mf):
                tag = f" [{enc.value}]" if len(encodings) > 1 else ""
                print(f"    [{resp.status}] {resp.length:>7}B  {payload[:80]}{tag}")
            finding = self.evaluate(resp)
            finding.encoding = enc
            if finding.confirmed:
                return finding
            last = finding
        return last

    async def run(self, client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for payload in self.payloads():
            finding = await self._send_eval(client, payload)
            if finding.confirmed:
                findings.append(finding)
        return self.dedup(findings)
