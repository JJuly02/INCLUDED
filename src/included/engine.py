"""INCLUDED engine — wires together config, client, and modules."""
from __future__ import annotations

import asyncio

from .config import Config
from .detection import Finding
from .http_client import HttpClient
from .modules import get_modules
from .modules.base import BaseModule


class Engine:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.module_classes = get_modules(cfg.modules)

    async def run(self) -> dict[str, list[Finding]]:
        results: dict[str, list[Finding]] = {}
        async with HttpClient(self.cfg) as client:
            modules = [cls(self.cfg) for cls in self.module_classes]

            async def run_one(m):
                if self.cfg.verbose:
                    print(f"\n[*] module: {m.name} — {m.description}")
                return await m.run(client)

            outcomes = await asyncio.gather(
                *(run_one(m) for m in modules), return_exceptions=True
            )
            for module, outcome in zip(modules, outcomes):
                results[module.name] = [] if isinstance(outcome, Exception) else outcome

            if self.cfg.verify_findings:
                await self._verify(results, modules, client)
        return results

    async def _verify(self, results: dict[str, list[Finding]],
                       modules: list[BaseModule], client: HttpClient) -> None:
        """One isolated, sequential re-fetch per confirmed finding, run
        after the main (concurrent, so sometimes "noisy") scan finishes.

        Two reasons for this: confirm the result actually reproduces on
        its own (weeds out flukes from a burst of concurrent requests
        possibly tripping a WAF/rate limiter/race condition on a fragile
        target), and capture the full response body as evidence instead
        of the short preview taken during the main scan. Disable with
        --no-verify.

        Skipped for modules marked verifiable=False, since a plain
        client.send(payload) replay can't reproduce a POST body, extra
        headers, or a hosted shell that no longer exists once run() returns.
        """
        module_by_name = {m.name: m for m in modules}
        for name, findings in results.items():
            module = module_by_name[name]
            if not module.verifiable or not findings:
                continue
            if self.cfg.verbose:
                print(f"\n[*] verifying {len(findings)} finding(s) for {name}...")
            verified: list[Finding] = []
            for f in findings:
                resp = await client.send(f.payload)
                if self.cfg.verbose:
                    print(f"    [{resp.status}] {resp.length:>7}B  {f.payload[:80]}")
                refreshed = module.evaluate(resp)
                if refreshed.confirmed:
                    refreshed.evidence = resp.body[:2000].replace("\n", "\\n")
                    verified.append(refreshed)
            results[name] = verified
