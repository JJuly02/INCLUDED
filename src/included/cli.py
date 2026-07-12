"""INCLUDED — punkt wejścia CLI. Flagi w stylu ffuf/nmap.

Przykłady:
  included -w "http://host/index.php?language=INCLUDE"
  included -w "http://host/index.php?language=INCLUDE" -f /etc/passwd -v
  included -w "http://host/?p=INCLUDE" --profile rce --cmd "id" -b PHPSESSID=abc
  included -w "http://host/img.php?p=INCLUDE" -fs 0 -mc 200 -o out.json -of json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from .banner import render
from .config import Config, OSHint, Encoding, MatchFilter
from .engine import Engine
from .modules import REGISTRY, GROUPS


def _parse_kv(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in pairs:
        if ":" in p:
            k, v = p.split(":", 1)
        elif "=" in p:
            k, v = p.split("=", 1)
        else:
            raise argparse.ArgumentTypeError(f"zły format: {p}")
        out[k.strip()] = v.strip()
    return out


def _int_set(val: str | None) -> set[int] | None:
    if not val:
        return None
    return {int(x) for x in val.split(",") if x.strip()}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="included",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="INCLUDED — modularny skaner File Inclusion (LFI/RFI). "
                    "Wyłącznie na autoryzowanych celach.",
        epilog="Marker INCLUDE w URL wyznacza miejsce wstrzyknięcia, "
               "np. -w \"http://host/?page=INCLUDE\"",
    )
    # --- cel ---
    tgt = p.add_argument_group("cel")
    tgt.add_argument("-w", "--url", required=True, metavar="URL",
                     help="URL celu z markerem INCLUDE")
    tgt.add_argument("-p", "--param", metavar="NAME",
                     help="parametr do wstrzyknięcia (gdy brak INCLUDE w URL)")
    tgt.add_argument("-X", "--method", default="GET", metavar="M", help="metoda HTTP")
    tgt.add_argument("-d", "--data", metavar="BODY", help="body POST (może mieć INCLUDE)")

    # --- co czytamy ---
    rd = p.add_argument_group("cel odczytu")
    rd.add_argument("-f", "--file", metavar="PATH",
                    help="konkretny plik/ścieżka do przetestowania (celowanie)")
    rd.add_argument("-W", "--wordlist", metavar="FILE",
                    help="lista plików-celów (jeden na linię)")

    # --- sesja ---
    ses = p.add_argument_group("sesja")
    ses.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                     help="nagłówek (wielokrotnie)")
    ses.add_argument("-b", "--cookie", action="append", default=[], metavar="'k=v'",
                     help="ciasteczko (wielokrotnie); PHPSESSID włącza session poisoning")
    ses.add_argument("--proxy", metavar="URL", help="proxy, np. http://127.0.0.1:8080")

    # --- techniki ---
    tech = p.add_argument_group("techniki")
    tech.add_argument("-m", "--module", action="append", default=[], metavar="NAME",
                      help=f"moduł (wielokrotnie): {', '.join(REGISTRY)}")
    tech.add_argument("--profile", choices=list(GROUPS), metavar="P",
                      help=f"gotowy zestaw: {', '.join(GROUPS)}")
    tech.add_argument("--os", choices=[o.value for o in OSHint], default="auto",
                      help="podpowiedź OS")
    tech.add_argument("-e", "--encode", choices=[e.value for e in Encoding], default="all",
                      help="wariant enkodingu payloadu")
    tech.add_argument("--depth", type=int, default=12, metavar="N", help="maks. głębokość ../")

    # --- RCE / RFI ---
    rce = p.add_argument_group("RCE / RFI")
    rce.add_argument("--cmd", default="id", metavar="CMD",
                     help="komenda dla web-shell/expect (domyślnie: id)")
    rce.add_argument("--lhost", metavar="IP", help="twój host dla RFI")
    rce.add_argument("--lport", type=int, metavar="PORT", help="twój port dla RFI")

    # --- match/filter (styl ffuf) ---
    mf = p.add_argument_group("match / filter")
    mf.add_argument("-mc", metavar="CODES", help="pokaż tylko te status code (200,301)")
    mf.add_argument("-fc", metavar="CODES", help="ukryj te status code (404,403)")
    mf.add_argument("-ms", metavar="SIZES", help="pokaż tylko te rozmiary")
    mf.add_argument("-fs", metavar="SIZES", help="ukryj te rozmiary (odsiej szum: 0)")
    mf.add_argument("-mr", metavar="REGEX", help="pokaż tylko pasujące do regexa")
    mf.add_argument("-fr", metavar="REGEX", help="ukryj pasujące do regexa")

    # --- wydajność / output ---
    io = p.add_argument_group("wydajność / output")
    io.add_argument("-t", "--threads", type=int, default=40, metavar="N",
                    help="współbieżność")
    io.add_argument("--timeout", type=float, default=10.0, metavar="S")
    io.add_argument("-v", "--verbose", action="store_true", help="pokaż każdy request")
    io.add_argument("-o", "--output", metavar="FILE", help="zapis wyników")
    io.add_argument("-of", "--output-format", choices=["text", "json"], default="text")
    io.add_argument("--all-hits", action="store_true",
                    help="wyłącz dedup — pokaż każde potwierdzone trafienie, nie tylko pierwsze per plik")
    io.add_argument("--no-banner", action="store_true")
    io.add_argument("--version", action="version", version=f"included {__version__}")
    return p


def build_config(args) -> Config:
    modules = list(args.module)
    if args.profile:
        modules = GROUPS[args.profile]
    return Config(
        url=args.url, method=args.method.upper(), param=args.param, data=args.data,
        target_file=args.file, wordlist=args.wordlist,
        headers=_parse_kv(args.header), cookies=_parse_kv(args.cookie), proxy=args.proxy,
        os_hint=OSHint(args.os), encoding=Encoding(args.encode),
        max_depth=args.depth, concurrency=args.threads, timeout=args.timeout,
        verbose=args.verbose, cmd=args.cmd, lhost=args.lhost, lport=args.lport,
        modules=modules,
        mf=MatchFilter(
            match_codes=_int_set(args.mc), filter_codes=_int_set(args.fc),
            match_size=_int_set(args.ms), filter_size=_int_set(args.fs),
            match_regex=args.mr, filter_regex=args.fr,
        ),
        output=args.output, output_format=args.output_format, all_hits=args.all_hits,
    )


def _report(results: dict, cfg: Config) -> int:
    total = 0
    lines = []
    for module, findings in results.items():
        if not findings:
            print(f"[ ] {module:<12} — brak potwierdzonych trafień")
            continue
        for f in findings:
            total += 1
            print(f"[+] {module:<12} — {f.signal}  (HTTP {f.status}, {f.length}B)")
            print(f"      payload : {f.payload}")
            print(f"      dowód   : {f.evidence[:120]}")
            lines.append({
                "module": module, "signal": f.signal, "payload": f.payload,
                "status": f.status, "length": f.length, "evidence": f.evidence,
            })
    print(f"\nPodsumowanie: {total} potwierdzonych trafień.")

    if cfg.output:
        with open(cfg.output, "w", encoding="utf-8") as fh:
            if cfg.output_format == "json":
                json.dump(lines, fh, ensure_ascii=False, indent=2)
            else:
                for l in lines:
                    fh.write(f"[{l['module']}] {l['signal']} :: {l['payload']}\n")
        print(f"[*] Zapisano do {cfg.output} ({cfg.output_format})")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.no_banner:
        print(render(__version__))
    cfg = build_config(args)
    active = cfg.modules or list(REGISTRY)
    print(f"[*] Cel   : {cfg.target_summary()}")
    print(f"[*] Moduły: {', '.join(active)}")
    print(f"[*] Enkod : {cfg.encoding.value} | głębokość: {cfg.max_depth} | wątki: {cfg.concurrency}")
    try:
        results = asyncio.run(Engine(cfg).run())
    except KeyboardInterrupt:
        print("\n[!] Przerwano.", file=sys.stderr)
        return 130
    return _report(results, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
