"""Async HTTP client for INCLUDED.

  * injects the payload in place of the INCLUDE marker (URL / param / body),
  * handles encoding variants (url / double-url),
  * shared session + concurrency semaphore,
  * returns a normalized Response for detection.
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
    """Return the payload encoded per the selected variant."""
    if enc == Encoding.NONE:
        return payload
    if enc == Encoding.URL:
        return quote(payload, safe="")
    if enc == Encoding.DOUBLE_URL:
        return quote(quote(payload, safe=""), safe="")
    return payload  # ALL is fanned out into individual variants upstream


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
        """Send one payload. encoding=None -> use the config default.

        extra_headers lets modules (e.g. log poisoning) inject the payload
        into a header instead of the URL.
        """
        assert self._session is not None, "use the client inside 'async with'"
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
