"""Run a controlled QNX compiler/image migration lab. Never build external projects."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys

from qnx_evidence_receipt import create_receipt, digest, file_hash, unique_pairs, verify_receipt
from qnx_migration_audit import scan

BASE = Path(__file__).resolve().parent
CASES = {
    "auxbase": ("QNX8-CC-001", "compiler_failure_to_success"),
    "ids": ("QNX8-SRC-002", "strict_compiler_failure_to_success"),
    "interrupt": ("QNX8-SRC-001", "both_compile_runtime_unverified"),
    "data": ("QNX8-BLD-001", "image_warning_to_clean"),
    "stack": ("QNX8-NET-001", "image_failure_to_success"),
}
IFS = {
    "data": ("[data=c]\nproof.txt={\nMigration proof\n}\n",
             "proof.txt={\nMigration proof\n}\n"),
    "stack": ("io-pkt-v6-hc\n", "io-sock\n"),
}
TOOLS = ("qnx_migration_lab.py", "qnx_migration_proof.py", "qnx_evidence_receipt.py",
         "qnx_migration_audit.py", "qnx_migration_report.py")
SCHEMA = "qnx-migration-lab/v0.1"


def sdk_env(sdk):
    path = sdk.resolve() / "qnxsdp-env.bat"
    if sys.platform != "win32" or not path.is_file():
        raise ValueError("Installed Windows QNX SDP required")
    if any(c in str(path) for c in '%!"&|<>^\r\n'):
        raise ValueError("Unsupported SDK path characters")
    return path


def ifs_case(root, env, name, stage, body):
    directory = root / name / stage
    directory.mkdir(parents=True)
    source = directory / "image.build"
    source.write_text(body, encoding="ascii")
    cmd = "mkifs -nn image.build proof.ifs"
    batch = directory / "build.cmd"
    batch.write_text(f'@echo off\ncall "{env}" >nul\nif errorlevel 1 exit /b 91\n@echo off\nset PROCESSOR=x86_64\n{cmd}\nexit /b %errorlevel%\n', encoding="ascii")
    p = subprocess.run(["cmd.exe", "/d", "/c", "build.cmd"], cwd=directory,
                       capture_output=True, text=True, errors="replace", timeout=60)
    artifact = directory / "proof.ifs"
    return dict(case=name, stage=stage, rule=CASES[name][0], command=cmd,
                exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr,
                findings=[f.rule_id for f in scan(directory)[0]],
                source_sha256=file_hash(source),
                binary_sha256=file_hash(artifact) if artifact.is_file() else None)


def classify(name, a, b):
    """Match exact expected outcome, not merely a successful process exit."""
    rule, observation = CASES[name]
    if (a["findings"] != [rule] or b["findings"] or b["exit_code"] != 0
            or not b["binary_sha256"]):
        return "unexpected_observation"
    old, new = a["stderr"].lower(), b["stderr"].lower()
    if name == "auxbase":
        ok = a["exit_code"] != 0 and "unrecognized command-line option '-auxbase'" in old
    elif name == "ids":
        ok = a["exit_code"] != 0 and "implicit declaration" in old and "set_ids_from_arg" in old
    elif name == "interrupt":
        ok = a["exit_code"] == 0 and bool(a["binary_sha256"])
    elif name == "data":
        ok = (a["exit_code"] == 0 and "attribute is no longer supported" in old
              and not new.strip() and a["binary_sha256"] == b["binary_sha256"])
    elif name == "stack":
        ok = a["exit_code"] != 0 and "io-pkt-v6-hc" in old and "not available" in old
    else:
        ok = False
    return observation if ok else "unexpected_observation"


def files_manifest(root):
    # Local lab output only. Reject linked files/directories, do not follow them.
    rows = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("Unexpected link in lab output")
        if path.is_file() and path != root / "lab.json":
            rows[path.relative_to(root).as_posix()] = file_hash(path)
    return rows


def run_lab(sdk, root):
    env = sdk_env(sdk)
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    compiler = root / "compiler"
    p = subprocess.run([sys.executable, str(BASE / "qnx_migration_proof.py"),
                        "--sdk", str(sdk.resolve()), "--output", str(compiler)],
                       capture_output=True, text=True, errors="replace", timeout=180)
    (root / "compiler-run.json").write_text(json.dumps(
        {"exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}, indent=2), encoding="utf-8")
    rows = json.loads((compiler / "results.json").read_text(encoding="utf-8"))
    images = root / "images"
    for name, stages in IFS.items():
        for stage, body in zip(("before", "after"), stages):
            rows.append(ifs_case(images, env, name, stage, body))
    results = []
    for name, (rule, expected) in CASES.items():
        a, b = [row for row in rows if row["case"] == name]
        parent = (images if name in IFS else compiler) / name
        receipt = create_receipt(parent / "before", sdk, compare=parent / "after")
        actual = classify(name, a, b)
        results.append(dict(case=name, rule=rule, observation=actual, expected=expected,
                            before=a, after=b, receipt=receipt))
    payload = dict(schema=SCHEMA, scope="controlled original synthetic fixtures only",
                   target="x86_64", runtime="not_run",
                   tool_files={n:file_hash(BASE/n) for n in TOOLS},
                   compiler_runner_exit=p.returncode, cases=results,
                   files=files_manifest(root),
                   limitations=["Unsigned local evidence; not trusted execution attestation.",
                                "No external project build, bootable image or runtime test.",
                                "SDK-derived binaries are local evidence; do not redistribute."])
    bundle = dict(payload=payload, sha256=digest(payload))
    (root / "lab.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle


def verify_lab(root, sdk, expected=None):
    root = root.resolve()
    bundle = json.loads((root/"lab.json").read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    payload = bundle["payload"]
    if payload.get("schema") != SCHEMA or digest(payload) != bundle["sha256"]:
        return False, "lab digest mismatch"
    if expected and expected.lower() != bundle["sha256"]:
        return False, "independent digest mismatch"
    if payload["files"] != files_manifest(root):
        return False, "local build evidence changed"
    if payload["tool_files"] != {n:file_hash(BASE/n) for n in TOOLS}:
        return False, "tool implementation changed"
    if [c["case"] for c in payload["cases"]] != list(CASES):
        return False, "case list mismatch"
    for row in payload["cases"]:
        name = row["case"]
        parent = root / ("images" if name in IFS else "compiler") / name
        ok, message = verify_receipt(row["receipt"], parent/"before", sdk, compare=parent/"after")
        if not ok:
            return False, name + ": " + message
        if row["observation"] != classify(name,row["before"],row["after"]):
            return False, "classification mismatch"
    return True, "local build evidence hashes and scoped source/SDK replay match; no rebuild performed"


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["run","verify"])
    p.add_argument("--sdk",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--expected-sha256")
    args=p.parse_args(argv)
    try:
        if args.action=="verify":
            ok,msg=verify_lab(args.output,args.sdk,args.expected_sha256)
            print(msg)
            return 0 if ok else 1
        if args.expected_sha256:
            p.error("--expected-sha256 requires verify")
        b=run_lab(args.sdk,args.output)
        for row in b["payload"]["cases"]:
            print(f'{row["case"]}: {row["before"]["exit_code"]} -> {row["after"]["exit_code"]} | {row["observation"]}')
        print("LAB_SHA256="+b["sha256"])
        return 0 if b["payload"]["compiler_runner_exit"]==0 and all(r["observation"]==r["expected"] for r in b["payload"]["cases"]) else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        p.error(str(exc))

if __name__=="__main__":
    sys.exit(main())
