"""Silnik INCLUDED — spina config, klienta i moduły."""
from __future__ import annotations

import asyncio

from .config import Config
from .detection import Finding
from .http_client import HttpClient
from .modules import get_modules


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
                    print(f"\n[*] moduł: {m.name} — {m.description}")
                return await m.run(client)

            outcomes = await asyncio.gather(
                *(run_one(m) for m in modules), return_exceptions=True
            )
            for module, outcome in zip(modules, outcomes):
                results[module.name] = [] if isinstance(outcome, Exception) else outcome
        return results
