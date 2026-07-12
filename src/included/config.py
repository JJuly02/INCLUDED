"""Central scan configuration for INCLUDED.

Every module receives a Config object. Adding an option = one field here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# Injection marker in the URL/param/body (the equivalent of FUZZ in ffuf).
#   included -w "http://host/index.php?language=INCLUDE"
INCLUDE = "INCLUDE"


class OSHint(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    AUTO = "auto"


class Encoding(str, Enum):
    """Payload encoding variants (character filter bypasses)."""
    NONE = "none"            # unchanged
    URL = "url"             # %2e%2e%2f
    DOUBLE_URL = "double"   # %252e%252e%252f
    ALL = "all"             # try all variants


@dataclass
class MatchFilter:
    """Response match/filter criteria — like -mc/-fc/-ms/-fs/-mr in ffuf.

    match_* = show ONLY what matches. filter_* = hide what matches.
    None = criterion inactive.
    """
    match_codes: set[int] | None = None      # -mc 200,301
    filter_codes: set[int] | None = None     # -fc 404,403
    match_size: set[int] | None = None       # -ms 1234
    filter_size: set[int] | None = None      # -fs 0,26        (strip empty/noise)
    match_regex: str | None = None           # -mr "root:.*:0:0"
    filter_regex: str | None = None          # -fr "not found"

    def has_criteria(self) -> bool:
        """Whether the user explicitly set at least one match/filter criterion."""
        return any((self.match_codes, self.filter_codes, self.match_size,
                    self.filter_size, self.match_regex, self.filter_regex))


@dataclass
class Config:
    # --- target ---
    url: str                                  # contains INCLUDE, or param gets appended
    method: str = "GET"
    param: str | None = None
    data: str | None = None

    # --- what we read ---
    # Explicitly given file/path to test (your -f/--file).
    # If set, modules target this instead of iterating a wordlist.
    target_file: str | None = None
    wordlist: str | None = None               # -W: list of target files to try

    # --- session / auth ---
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None

    # --- behavior ---
    os_hint: OSHint = OSHint.AUTO
    encoding: Encoding = Encoding.ALL
    max_depth: int = 12
    concurrency: int = 40
    timeout: float = 10.0
    verify_tls: bool = False
    verbose: bool = False
    delay: float = 0.0                        # --delay: min seconds between request starts (rate limit)

    # --- RCE / RFI (opt-in, need your own host/listener) ---
    cmd: str = "id"                           # command for web-shell/expect payloads
    lhost: str | None = None                  # --lhost for RFI (your server)
    lport: int | None = None                  # --lport

    # --- modules ---
    modules: list[str] = field(default_factory=list)   # empty = all

    # --- match/filter ---
    mf: MatchFilter = field(default_factory=MatchFilter)

    # --- output ---
    output: str | None = None                 # -o file
    output_format: str = "text"               # -of text|json
    all_hits: bool = False                    # --all-hits: disable dedup per (module, signal, evidence)
    verify_findings: bool = True              # --no-verify to disable: one clean re-fetch per confirmed finding

    def target_summary(self) -> str:
        s = f"{self.method} {self.url}"
        if self.param:
            s += f"  (param={self.param})"
        if self.target_file:
            s += f"  (file={self.target_file})"
        return s
