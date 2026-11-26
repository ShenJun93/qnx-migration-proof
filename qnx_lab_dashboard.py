"""Render verified, local controlled-lab evidence in the offline review."""
from __future__ import annotations
import html
import json
from pathlib import Path
from qnx_evidence_receipt import digest, unique_pairs
from qnx_migration_lab import verify_lab, CASES

LABELS = {
    "compiler_failure_to_success": "Compiler failure to success",
    "strict_compiler_failure_to_success": "Strict compiler failure to success",
    "both_compile_runtime_unverified": "Both build; runtime unverified",
    "image_warning_to_clean": "Image warning removed; identical IFS",
    "image_failure_to_success": "Image packaging failure to success",
    "unexpected_observation": "Unexpected observation",
}
NAMES = {"auxbase":"Compiler flags", "ids":"Driver identity API", "interrupt":"Interrupt lifecycle",
         "data":"Image buildfile attribute", "stack":"Network stack packaging"}

def e(value):
    return html.escape(str(value), quote=True)

def load_verified_lab(root: Path, sdk: Path, expected: str):
    if not expected or len(expected) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected):
        raise ValueError("An independently retained 64-character lab digest is required")
    before = (root/"lab.json").read_bytes()
    ok, msg = verify_lab(root, sdk, expected)
    if not ok:
        raise ValueError("Lab verification rejected: " + msg)
    if before != (root/"lab.json").read_bytes():
        raise ValueError("Lab changed during verification")
    bundle = json.loads(before, object_pairs_hook=unique_pairs)
    if digest(bundle["payload"]) != expected.lower():
        raise ValueError("Lab digest changed")
    return bundle

def stage_html(name, row):
    log = (row["stdout"]+"\n"+row["stderr"]).strip() or "No diagnostics"
    return f'<div class="lab-stage"><h3>{e(name)} / exit {e(row["exit_code"])}</h3><p class="small">Scanner candidates: {len(row["findings"])}</p><pre>{e(row["command"])}</pre><pre>{e(log)}</pre><p class="small hash">Output SHA-256: {e(row["binary_sha256"] or "No output recorded")}</p></div>'

def lab_html(bundle):
    payload = bundle["payload"]
    rows = payload["cases"]
    matched = sum(row["observation"] == CASES[row["case"]][1] for row in rows)
    cards=[]
    for row in rows:
        name=row["case"]
        label=LABELS.get(row["observation"],"Unexpected observation")
        cards.append(f'''<details class="lab-case"><summary><strong>{e(NAMES[name])}</strong><span class="lab-result">{e(label)}</span></summary>
<div class="lab-stages">{stage_html("Before",row["before"])}{stage_html("After",row["after"])}</div>
<p class="small hash">Scoped receipt: {e(row["receipt"]["sha256"])}</p></details>''')
    return f'''<section class="panel" id="controlled-lab"><div class="eyebrow">Separate controlled experiment</div><h2>Live SDK build evidence</h2>
<p>Previously executed original synthetic fixture pairs, verified at report generation against the supplied lab digest and local source, SDK and output hashes. This is NOT a build of the project in the remediation queue.</p>
<div class="lab-banner"><strong>{matched}/{len(rows)} expected observations matched</strong><span>Target x86_64 / runtime NOT RUN</span></div>
<p class="small">Verification: scoped replay matched at generation. No rebuild or trusted execution attestation. The HTML itself does not verify live.</p>
{"".join(cards)}
<p class="small hash">Lab payload SHA-256: {e(bundle["sha256"])}</p>
<p class="small">Image outputs are non-bootable fixtures. SDK-derived binaries remain local.</p></section>'''
