"""Centralna konfiguracja skanu INCLUDED.

Wszystkie moduły dostają obiekt Config. Dodanie opcji = jedno pole tutaj.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# Marker wstrzyknięcia w URL/param/body (odpowiednik FUZZ w ffuf).
#   included -w "http://host/index.php?language=INCLUDE"
INCLUDE = "INCLUDE"


class OSHint(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    AUTO = "auto"


class Encoding(str, Enum):
    """Warianty enkodingu payloadu (bypassy filtrów znaków)."""
    NONE = "none"            # bez zmian
    URL = "url"             # %2e%2e%2f
    DOUBLE_URL = "double"   # %252e%252e%252f
    ALL = "all"             # wypróbuj wszystkie


@dataclass
class MatchFilter:
    """Kryteria match/filter odpowiedzi — jak -mc/-fc/-ms/-fs/-mr w ffuf.

    match_* = pokaż TYLKO to co pasuje. filter_* = ukryj to co pasuje.
    None = kryterium nieaktywne.
    """
    match_codes: set[int] | None = None      # -mc 200,301
    filter_codes: set[int] | None = None     # -fc 404,403
    match_size: set[int] | None = None       # -ms 1234
    filter_size: set[int] | None = None      # -fs 0,26        (odsiej pustki/szum)
    match_regex: str | None = None           # -mr "root:.*:0:0"
    filter_regex: str | None = None          # -fr "not found"


@dataclass
class Config:
    # --- cel ---
    url: str                                  # zawiera INCLUDE albo param jest doklejany
    method: str = "GET"
    param: str | None = None
    data: str | None = None

    # --- co czytamy ---
    # Jawnie wskazany plik/ścieżka do przetestowania (twój -f/--file).
    # Jeśli podany, moduły celują w to zamiast strzelać wordlistą.
    target_file: str | None = None
    wordlist: str | None = None               # -W: lista plików-celów do sprawdzenia

    # --- sesja / uwierzytelnienie ---
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None

    # --- zachowanie ---
    os_hint: OSHint = OSHint.AUTO
    encoding: Encoding = Encoding.ALL
    max_depth: int = 12
    concurrency: int = 40
    timeout: float = 10.0
    verify_tls: bool = False
    verbose: bool = False

    # --- RCE / RFI (opt-in, wymagają Twojego hosta/listenera) ---
    cmd: str = "id"                           # komenda dla web-shell/expect payloadów
    lhost: str | None = None                  # --lhost do RFI (twój serwer)
    lport: int | None = None                  # --lport

    # --- moduły ---
    modules: list[str] = field(default_factory=list)   # puste = wszystkie

    # --- match/filter ---
    mf: MatchFilter = field(default_factory=MatchFilter)

    # --- output ---
    output: str | None = None                 # -o plik
    output_format: str = "text"               # -of text|json
    all_hits: bool = False                    # --all-hits: wyłącz dedup per (moduł, sygnał, dowód)

    def target_summary(self) -> str:
        s = f"{self.method} {self.url}"
        if self.param:
            s += f"  (param={self.param})"
        if self.target_file:
            s += f"  (file={self.target_file})"
        return s
