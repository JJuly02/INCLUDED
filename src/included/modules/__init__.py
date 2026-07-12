"""Technique module registry for INCLUDED.

Categories:
  read  — file/source disclosure (traversal, filter_read)
  rce   — code execution (data, input, expect, zip_phar, log_poison, filter_chain_rce, rfi)
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
from .rfi import RFIModule

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
        RFIModule,
    )
}

# Quick-selection groups: --profile read / rce / all
GROUPS: dict[str, list[str]] = {
    "read": ["traversal", "filter_read"],
    "rce": ["data", "input", "expect", "zip_phar", "log_poison", "filter_chain_rce", "rfi"],
    "all": list(REGISTRY),
}


def get_modules(names: list[str] | None) -> list[type[BaseModule]]:
    if not names:
        return list(REGISTRY.values())
    selected = []
    for n in names:
        if n not in REGISTRY:
            raise KeyError(f"unknown module: {n} (available: {', '.join(REGISTRY)})")
        selected.append(REGISTRY[n])
    return selected
