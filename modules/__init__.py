"""Rejestr modułów technik INCLUDED.

Kategorie:
  read  — odczyt plików/źródeł (traversal, filter_read)
  rce   — wykonanie kodu (data, input, expect, zip_phar, log_poison, filter_chain_rce)
"""
from __future__ import annotations

from .base import BaseModule
from .traversal import TraversalModule
from .wrappers import (
    FilterReadModule, DataWrapperModule, ExpectWrapperModule,
    InputWrapperModule, ZipPharModule,
)
from .log_poison import LogPoisonModule
from .filter_chain import FilterChainRCEModule

REGISTRY: dict[str, type[BaseModule]] = {
    m.name: m
    for m in (
        TraversalModule,
        FilterReadModule,
        DataWrapperModule,
        InputWrapperModule,
        ExpectWrapperModule,
        ZipPharModule,
        LogPoisonModule,
        FilterChainRCEModule,
    )
}

# Grupy do szybkiego wyboru: --profile read / rce / all
GROUPS: dict[str, list[str]] = {
    "read": ["traversal", "filter_read"],
    "rce": ["data", "input", "expect", "zip_phar", "log_poison", "filter_chain_rce"],
    "all": list(REGISTRY),
}


def get_modules(names: list[str] | None) -> list[type[BaseModule]]:
    if not names:
        return list(REGISTRY.values())
    selected = []
    for n in names:
        if n not in REGISTRY:
            raise KeyError(f"nieznany moduł: {n} (dostępne: {', '.join(REGISTRY)})")
        selected.append(REGISTRY[n])
    return selected
