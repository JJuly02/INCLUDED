"""Banner ASCII dla INCLUDED."""
from __future__ import annotations

BANNER = r"""
 ___ _   _  ___ _   _   _ ___  ___ ___
|_ _| \ | |/ __| | | | | |   \| __|   \
 | ||  \| | (__| |_| |_| | |) | _|| |) |
|___|_|\__|\___|____\___/|___/|___|___/
     you've been INCLUDED.   v{ver}
"""


def render(version: str) -> str:
    return BANNER.replace("{ver}", version)
