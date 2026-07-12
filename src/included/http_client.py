"""Async HTTP client for INCLUDED.

  * injects the payload in place of the INCLUDE marker (URL / param / body),
  * handles encoding variants (url / double-url),
  * shared session + concurrency semaphore,
  * returns a normalized Response for detection.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

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


def _percent_encode_all(s: str) -> str:
    """Percent-encode every byte, including '.', '-', '_', '~'.

    Unlike urllib.parse.quote(), which always treats those four as
    "unreserved" and leaves them alone no matter what `safe` is set to.
    That's backwards for bypassing a naive input filter: a blacklist
    checking for a literal '.' or '/' after one decode pass needs THOSE
    exact characters hidden, and quote()-based double-encoding never hides
    a dot at any depth (verified: quote(quote("../x")) still contains "..").
    """
    return "".join(f"%{b:02X}" for b in s.encode("utf-8"))


def encode_payload(payload: str, enc: Encoding) -> str:
    """Return the payload encoded per the selected variant."""
    if enc == Encoding.NONE:
        return payload
    if enc == Encoding.URL:
        return _percent_encode_all(payload)
    if enc == Encoding.DOUBLE_URL:
        return _percent_encode_all(_percent_encode_all(payload))
    return payload  # ALL is fanned out into individual variants upstream


def build_request(cfg: Config, payload: str, *, encoding: Encoding | None = None) -> tuple[str, str | None]:
    """Build the (url, body) that sending this payload would produce.

    Shared by HttpClient.send() and the CLI's reproduction ("curl this")
    output, so the two never drift apart.
    """
    enc = encoding if encoding is not None else cfg.encoding
    encoded = encode_payload(payload, enc)
    url, body = cfg.url, cfg.data
    if INCLUDE in url:
        url = url.replace(INCLUDE, encoded)
    elif cfg.param:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{cfg.param}={encoded}"
    if body and INCLUDE in body:
        body = body.replace(INCLUDE, encoded)
    return url, body


class HttpClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._session: aiohttp.ClientSession | None = None
        # Global rate limit (--delay): a lock-serialized "earliest next send
        # time" cursor, so the cap is on aggregate requests/sec regardless
        # of --threads, not just a per-request sleep that concurrency would
        # make meaningless (40 workers each sleeping 0.1s still fire ~40
        # requests every 0.1s, not 1).
        self._rate_lock = asyncio.Lock()
        self._next_send_at = 0.0

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

    async def _throttle(self) -> None:
        if self.cfg.delay <= 0:
            return
        async with self._rate_lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            wait = self._next_send_at - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = self._next_send_at
            self._next_send_at = now + self.cfg.delay

    async def send(self, payload: str, *, encoding: Encoding | None = None,
                   extra_headers: dict[str, str] | None = None) -> Response:
        """Send one payload. encoding=None -> use the config default.

        extra_headers lets modules (e.g. log poisoning) inject the payload
        into a header instead of the URL.
        """
        assert self._session is not None, "use the client inside 'async with'"
        url, body = build_request(self.cfg, payload, encoding=encoding)

        await self._throttle()
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
