"""Async klient HTTP dla INCLUDED.

  * wstrzykuje payload w miejsce markera INCLUDE (URL / param / body),
  * obsługuje warianty enkodingu (url / double-url),
  * współdzielona sesja + semafor współbieżności,
  * zwraca znormalizowany Response dla detekcji.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import quote

import aiohttp

from .config import Config, INCLUDE, Encoding


@dataclass
class Response:
    status: int
    body: str
    length: int
    headers: dict[str, str]
    payload: str
    url: str
    error: str | None = None


def encode_payload(payload: str, enc: Encoding) -> str:
    """Zwraca payload zakodowany wg wybranego wariantu."""
    if enc == Encoding.NONE:
        return payload
    if enc == Encoding.URL:
        return quote(payload, safe="")
    if enc == Encoding.DOUBLE_URL:
        return quote(quote(payload, safe=""), safe="")
    return payload  # ALL rozbijamy wyżej na pojedyncze warianty


class HttpClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "HttpClient":
        connector = aiohttp.TCPConnector(ssl=self.cfg.verify_tls, limit=self.cfg.concurrency)
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers=self.cfg.headers,
            cookies=self.cfg.cookies,
            timeout=aiohttp.ClientTimeout(total=self.cfg.timeout),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    def _inject(self, encoded: str) -> tuple[str, str | None]:
        url, body = self.cfg.url, self.cfg.data
        if INCLUDE in url:
            url = url.replace(INCLUDE, encoded)
        elif self.cfg.param:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{self.cfg.param}={encoded}"
        if body and INCLUDE in body:
            body = body.replace(INCLUDE, encoded)
        return url, body

    async def send(self, payload: str, *, encoding: Encoding | None = None,
                   extra_headers: dict[str, str] | None = None) -> Response:
        """Wysyła jeden payload. encoding=None -> użyj domyślnego z configu.

        extra_headers pozwala modułom (np. log poisoning) wstrzyknąć
        payload w nagłówek zamiast w URL.
        """
        assert self._session is not None, "użyj klienta w 'async with'"
        enc = encoding if encoding is not None else self.cfg.encoding
        encoded = encode_payload(payload, enc)
        url, body = self._inject(encoded)

        async with self._sem:
            try:
                async with self._session.request(
                    self.cfg.method, url, data=body,
                    headers=extra_headers, allow_redirects=False,
                ) as resp:
                    text = await resp.text(errors="replace")
                    return Response(
                        status=resp.status, body=text, length=len(text),
                        headers=dict(resp.headers), payload=payload, url=url,
                    )
            except Exception as exc:
                return Response(0, "", 0, {}, payload, url, error=str(exc))
