"""Kontrakt modułu techniki dla INCLUDED.

Nowa technika = podklasa BaseModule + wpis w rejestrze. Silnik nie zna
szczegółów — pyta o payloady, wysyła, ocenia.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from ..config import Config, OSHint
from ..detection import Finding, check, should_show
from ..http_client import HttpClient, Response

_WORDLIST_DIR = Path(__file__).resolve().parent.parent / "wordlists"

# Awaryjne cele, gdyby wordlists/*.txt nie było w danej instalacji (np. paczka
# bez plików danych) — normalnie DEFAULT_TARGETS ładuje się z tych plików.
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


# Domyślne cele per OS (gdy user nie podał -f/--file ani -W/--wordlist).
# Ładowane z wordlists/linux.txt i wordlists/windows.txt.
DEFAULT_TARGETS = {
    OSHint.LINUX: _load_wordlist("linux.txt", OSHint.LINUX),
    OSHint.WINDOWS: _load_wordlist("windows.txt", OSHint.WINDOWS),
}


class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    expect_base64: bool = False

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def targets(self) -> list[str]:
        """Lista plików-celów. Priorytet: -f > -W > domyślne per OS."""
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
        return check(resp, expect_base64=self.expect_base64)

    def dedup(self, findings: list[Finding]) -> list[Finding]:
        """Zostaw tylko pierwsze potwierdzenie per (sygnał, dowód) — ten sam
        plik trafiony różnymi wariantami payloadu (głębokość/encoding/bypass)
        daje identyczny dowód, więc to wystarcza jako klucz "ten sam plik".
        Wyłączane przez --all-hits.
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

    async def run(self, client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for payload in self.payloads():
            resp = await client.send(payload)
            if self.cfg.verbose and should_show(resp, self.cfg.mf):
                print(f"    [{resp.status}] {resp.length:>7}B  {payload[:80]}")
            finding = self.evaluate(resp)
            if finding.confirmed:
                findings.append(finding)
        return self.dedup(findings)
