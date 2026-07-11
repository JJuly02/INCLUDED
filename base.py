"""Kontrakt modułu techniki dla INCLUDED.

Nowa technika = podklasa BaseModule + wpis w rejestrze. Silnik nie zna
szczegółów — pyta o payloady, wysyła, ocenia.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from ..config import Config, OSHint
from ..detection import Finding, check, should_show
from ..http_client import HttpClient, Response

# Domyślne cele per OS (gdy user nie podał -f/--file ani -W/--wordlist).
DEFAULT_TARGETS = {
    OSHint.LINUX: [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ", "/proc/self/cmdline",
        "/var/www/html/config.php",
    ],
    OSHint.WINDOWS: [
        "C:/Windows/win.ini", "C:/boot.ini",
        "C:/Windows/System32/drivers/etc/hosts",
    ],
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

    async def run(self, client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for payload in self.payloads():
            resp = await client.send(payload)
            if self.cfg.verbose and should_show(resp, self.cfg.mf):
                print(f"    [{resp.status}] {resp.length:>7}B  {payload[:80]}")
            finding = self.evaluate(resp)
            if finding.confirmed:
                findings.append(finding)
        return findings
