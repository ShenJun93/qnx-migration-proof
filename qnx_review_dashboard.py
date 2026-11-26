"""Generate a self-contained offline review from a fresh migration scan."""
from __future__ import annotations
import argparse
import html
from pathlib import Path
from qnx_migration_plan import make_plan
from qnx_lab_dashboard import load_verified_lab, lab_html

BASE = Path(__file__).resolve().parent
TITLES = {
    "QNX8-NET-001":"Networking stack", "QNX8-NET-002":"Network device driver",
    "QNX8-NET-003":"DHCP and DNS", "QNX8-CRYPTO-001":"Cryptography plugin",
    "QNX8-BLD-001":"Image buildfile", "QNX8-SRC-001":"Interrupt lifecycle",
    "QNX8-SRC-002":"Driver identity API", "QNX8-SRC-003":"I2C commands",
    "QNX8-CC-001":"Compiler flags",
}
STATES = {
    "baseline_only":"Baseline only",
    "comparison_only_candidate":"Candidate in comparison only",
    "not_observed_in_comparison":"Not observed in comparison",
    "comparison_incomplete":"Comparison incomplete",
    "candidates_remain_in_comparison":"Candidates remain",
}

def e(value):
    return html.escape(str(value), quote=True)

def artifact_rows(artifacts):
    return "".join(f'<div class="inv"><code>{e(name)}</code><span class="state">{e(info["status"].replace("_"," "))}</span></div>' for name,info in sorted(artifacts.items()))

def task_html(task):
    key=task["rule_id"]
    locations=[]
    for loc in task["locations"]:
        context="".join(f'<div class="small">SDK literal: {e(x["literal"])} = {e(x["sdk_observation"]["status"])} (reference, not dependency proof)</div>' for x in loc["literal_inventory_context"])
        locations.append(f'<div class="location"><code>{e(loc["path"])}:{e(loc["line"])}:{e(loc["column"])}</code><pre>{e(loc["excerpt"])}</pre>{context}<div class="small hash">Source SHA-256: {e(loc["source_sha256"])}</div></div>')
    fixture=task.get("historical_fixture_context")
    fixture_html=f'<p>Historical controlled fixture: {e(fixture["observation"].replace("_"," "))}. Not a build of this project.</p>' if fixture else ""
    replacement=task.get("replacement_examples",{})
    replacement_html=f'<div class="sub"><h3>SDK replacement examples</h3><p>Not automatic substitutions.</p>{artifact_rows(replacement)}</div>' if replacement else ""
    comparison=task["comparison_count"]
    count=f'{task["candidate_count"]} to {comparison}' if comparison is not None else str(task["candidate_count"])
    return f'''<details class="task" data-severity="{e(task["severity"])}"><summary><span class="summary"><span><span class="rule">{e(key)} / {e(task["severity"].upper())}</span><br><strong>{e(TITLES.get(key,key))}</strong><br><span class="badge">{e(STATES.get(task["review_state"],task["review_state"]))}</span></span><span class="count">{e(count)}</span></span></summary>
<div class="sub"><h3>Review action</h3><p>{e(task["action"])}</p><h3>Required validation</h3><p>{e(task["validation"])}</p><span class="badge">PROJECT VALIDATION: NOT RUN</span>{fixture_html}</div>{replacement_html}
<div class="sub"><h3>Source locations ({len(locations)})</h3>{"".join(locations) or "<p>No baseline locations.</p>"}</div><p class="small">Documentation: <code>{e(task["source"])}</code></p></details>'''

def render(bundle, lab=None):
    plan=bundle["plan"]
    report=bundle["receipt"]["payload"]["report"]
    src=report["source"]
    comp=report["comparison"]
    observed=report["sdk_inventory"]
    metrics=[("Baseline candidates",len(src["findings"])),("Comparison candidates",len(comp["findings"]) if comp is not None else "N/A"),("Review groups",len(plan["tasks"])),("Project validations run",0)]
    metric_html="".join(f'<div class="metric"><b>{e(v)}</b><span class="small">{e(k)}</span></div>' for k,v in metrics)
    sdk_html=f'<p>Target: {e(observed["target_arch"])}. Named-file inventory: {e("complete for checked names" if observed["complete_for_named_files"] else "incomplete")}. Release not independently identified by inventory.</p><div class="inventory">{artifact_rows(observed["artifacts"])}</div>' if observed else "<p>SDK inventory not requested.</p>"
    limits=list(dict.fromkeys(plan["limitations"]+report["limitations"]+bundle["receipt"]["payload"]["limitations"]))
    style=(BASE/"review_dashboard.css").read_text(encoding="utf-8")
    script=(BASE/"review_dashboard.js").read_text(encoding="utf-8")
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>QNX Migration Proof | Review</title><style>{style}</style></head><body><main><header><div class="eyebrow">Migration engineering / Offline review</div><h1>QNX Migration Proof</h1><p>Source candidates, installed SDK observations and replayable evidence.</p></header>
<div class="notice"><strong>Review evidence, not a compatibility certificate.</strong> No project build, target execution or automated patch was performed.</div><section class="metrics" aria-label="Review metrics">{metric_html}</section>
<p class="small">Scoped files: {e(src["inspected_files"])} baseline / {e(comp["inspected_files"] if comp is not None else "N/A")} comparison. Recognized skipped files: {e(plan["source_skips"])} / {e(plan["comparison_skips"] if comp is not None else "N/A")}.</p>
<h2>Remediation queue</h2><div class="toolbar"><label>Search groups<input id="query" type="search" placeholder="Rule, file or keyword"></label><label>Severity<select id="severity"><option value="all">All severities</option><option value="high">High</option><option value="medium">Medium</option></select></label><button id="expand" type="button">Expand visible</button><button id="collapse" type="button">Collapse all</button></div><p id="visible" aria-live="polite">{len(plan["tasks"])} review groups</p>
<section aria-label="Review groups">{"".join(task_html(t) for t in plan["tasks"]) or "<p>No scoped migration candidates observed.</p>"}</section>
{lab_html(lab) if lab is not None else ""}
<section class="panel"><h2>SDK inventory</h2>{sdk_html}</section>
<section class="panel"><h2>Evidence receipt</h2><p>Unsigned snapshot. Replay with the CLI against the same scoped inputs. This page does not perform live verification.</p><p class="small">Receipt payload SHA-256</p><code class="hash">{e(plan["receipt_sha256"])}</code><p class="small">Plan SHA-256</p><code class="hash">{e(bundle["plan_sha256"])}</code></section>
<section class="panel"><h2>Evidence boundaries</h2><ul>{"".join(f"<li>{e(item)}</li>" for item in limits)}</ul></section><footer>Generated locally. No network requests, telemetry, external assets or project modifications. HTML may contain source excerpts; review before sharing.</footer></main><script>{script}</script></body></html>'''

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path)
    p.add_argument("--compare",type=Path)
    p.add_argument("--sdk",type=Path)
    p.add_argument("--arch",choices=["x86_64","aarch64le"],default="x86_64")
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--lab",type=Path,help="Local controlled lab output directory")
    p.add_argument("--lab-sha256",help="Independently retained lab payload digest")
    args=p.parse_args(argv)
    try:
        if args.output.suffix.lower() != ".html":
            raise ValueError("Output must have .html extension")
        bundle=make_plan(args.source,args.sdk,args.arch,args.compare)
        if args.lab is not None and (args.sdk is None or args.arch != "x86_64" or not args.lab_sha256):
            p.error("--lab requires --sdk, x86_64 and --lab-sha256")
        if args.lab is None and args.lab_sha256:
            p.error("--lab-sha256 requires --lab")
        lab=load_verified_lab(args.lab,args.sdk,args.lab_sha256) if args.lab is not None else None
        page=render(bundle,lab)
        with args.output.open("x",encoding="utf-8",newline="\n") as out:
            out.write(page)
    except (ValueError,OSError,KeyError,TypeError) as exc:
        p.error(str(exc))
    print("Created offline review:",args.output)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
