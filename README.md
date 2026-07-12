# INCLUDED

> you've been INCLUDED.

Modular File Inclusion (LFI/RFI) scanner — modern techniques missing from
older tools (filter chains, two-phase log/session poisoning, filter bypass
variants). For use **only against authorized targets**
(HTB/CPTS labs, CTFs, your own environments, authorized pentests).

## Installation
```bash
git clone https://github.com/JJuly02/INCLUDED.git && cd INCLUDED && ./install.sh
```
Uses `pipx` if you have it, otherwise sets up a local `.venv/` — either
way it ends with a working `included` command.

<details>
<summary>No git on this box? (e.g. a locked-down pwnbox)</summary>

```bash
wget https://github.com/JJuly02/INCLUDED/archive/refs/heads/main.tar.gz
tar xzf main.tar.gz
cd INCLUDED-main
./install.sh
included --version
```
</details>

<details>
<summary>Manual install</summary>

```bash
# option A: as a CLI command
pipx install .          # or: pip install .
included --help

# option B: run in place, no install
pip install -r requirements.txt
PYTHONPATH=src python3 -m included --help
```
</details>

## Usage
The `INCLUDE` marker in the URL marks the injection point (like `FUZZ` in ffuf):

```bash
# basic scan with all modules
included -w "http://host/index.php?language=INCLUDE"

# target a specific file + verbose
included -w "http://host/?p=INCLUDE" -f /etc/passwd -v

# RCE techniques only, with a command and session (enables session poisoning)
included -w "http://host/?p=INCLUDE" --profile rce --cmd "id" -b PHPSESSID=abc123

# fuzzing with noise filtering, output to JSON
included -w "http://host/img.php?p=INCLUDE" -fs 0 -mc 200 -o out.json -of json

# use an external wordlist, e.g. SecLists, instead of the bundled defaults
included -w "http://host/?view=INCLUDE" -W /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 1935
```

By default, the output stays quiet: only confirmed findings and a summary.
Add `-v` to see every request as it's sent. Each confirmed finding gets one
extra, isolated re-fetch after the main scan to confirm it reproduces and
to capture the full response as evidence — disable with `--no-verify`.

`-W/--wordlist` accepts any plain text file, one path per line — including
SecLists' own LFI wordlists, not just the bundled `linux.txt`/`windows.txt`.

## Modules
| module             | group | what it does                                          |
|--------------------|-------|--------------------------------------------------------|
| `traversal`        | read  | ../ + bypasses (`....//`, `..././`, prefixes, encoding)|
| `filter_read`      | read  | `php://filter` — dumps source files as base64          |
| `data`             | rce   | `data://` web shell (allow_url_include)                 |
| `input`            | rce   | `php://input` — web shell in POST body                 |
| `expect`           | rce   | `expect://` — direct command execution                 |
| `zip_phar`         | rce   | `zip://` / `phar://` from an uploaded archive (`--file`)|
| `log_poison`       | rce   | two-phase: poison access.log/session, then include      |
| `filter_chain_rce` | rce   | `php://filter` chain — builds a PHP web shell in-flight, no file upload needed (adapted from [Synacktiv's technique](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it)); requires glibc `iconv` on the target (typical on Linux) |
| `rfi`              | rce   | Remote File Inclusion; with `--lhost/--lport` auto-hosts the web shell over HTTP for the target to fetch. `ftp://`/UNC payloads are generated too but need your own FTP/SMB server |

Profiles: `--profile read|rce|all`.

## Legal
Licensed under [Apache License 2.0](LICENSE). Third-party attribution
(the `filter_chain_rce` conversion table, adapted from Synacktiv's
research) is documented in [NOTICE](NOTICE).

This tool is for **authorized security testing only** — HTB/CPTS labs,
CTFs, your own environments, or engagements you're explicitly authorized
to test. Running it against systems you don't own or don't have written
permission to test is illegal in most jurisdictions. The authors take no
responsibility for misuse.

## Status
9 modules (read + RCE), auto-hosted RFI, and a filter-chain RCE generator,
all verified against real PHP targets. Packaged with a `pipx`-installable
console-script entry point.
