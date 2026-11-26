"""Read-only QNX migration evidence report. No project commands are executed."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import json
import os
from pathlib import Path

from qnx_migration_audit import RULES, scan_detailed

# Fixed, documented artifact checks, not automatic driver replacement mappings.
ARTIFACTS = {
    "QNX8-NET-001": (("io-pkt-v6-hc",), ("io-sock",)),
    "QNX8-NET-002": (("devnp-e1000.so",), ("devs-vtnet_pci.so",)),
    "QNX8-NET-003": (("dhclient", "autoipd", "rtsold"), ("dhcpcd",)),
    "QNX8-CRYPTO-001": (("qcrypto-openssl.so",), ("qcrypto-openssl-3.so",)),
}
FIXTURE_EVIDENCE = {
    "QNX8-CC-001": ("fixture_build_failure_to_success", "BH0354"),
    "QNX8-SRC-002": ("fixture_strict_build_failure_to_success", "BH0354"),
    "QNX8-SRC-001": ("fixture_both_builds_pass_runtime_unverified", "BH0354"),
}
LIMITS = [
    "Static findings are migration candidates, not verified defects.",
    "Artifact checks concern named files in the selected installed target only.",
    "Missing artifacts do not establish absence from every SDK package.",
    "Fixture compiler results are historical observations, not builds of the scanned project.",
    "Rule counts do not measure precision, recall or independent defects.",
    "No project build, runtime, hardware compatibility or safety certification.",
    "Scanner scope and skips apply; zero findings is not a compatibility verdict.",
]


def is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def inventory(sdk: Path, arch: str) -> dict:
    target = sdk.resolve() / "target" / "qnx" / arch
    if not target.is_dir() or is_link(target):
        raise ValueError(f"Expected installed target directory: {target}")
    names = {name for pair in ARTIFACTS.values() for group in pair for name in group}
    paths = {name: [] for name in sorted(names)}
    skipped = 0
    errors = []

    def on_error(exc):
        errors.append(str(exc))

    for directory, dirs, files in os.walk(target, followlinks=False, onerror=on_error):
        base = Path(directory)
        kept = []
        for name in dirs:
            if is_link(base / name):
                skipped += 1
            else:
                kept.append(name)
        dirs[:] = kept
        for name in files:
            if name not in paths:
                continue
            path = base / name
            if is_link(path):
                skipped += 1
            elif path.is_file():
                paths[name].append(path.relative_to(target).as_posix())
            else:
                errors.append(f"Cannot inspect {path}")
    complete = not errors and not skipped
    return {
        "target_arch": arch,
        "target_root": str(target),
        "sdk_release": "not independently identified by inventory",
        "complete_for_named_files": complete,
        "skipped_links": skipped,
        "errors": errors,
        "artifacts": {
            name: {"status": "present" if found else "not_found" if complete else "unknown",
                   "paths": sorted(found)}
            for name, found in paths.items()
        },
    }


def make_report(root: Path, sdk: Path | None = None, arch: str = "x86_64",
                compare: Path | None = None) -> dict:
    findings, coverage = scan_detailed(root)
    files = coverage["inspected_files"]
    counts = Counter(f.rule_id for f in findings)
    other_counts = None
    comparison = None
    if compare is not None:
        other, other_coverage = scan_detailed(compare)
        other_files = other_coverage["inspected_files"]
        other_counts = Counter(f.rule_id for f in other)
        comparison = {
            "path": str(compare.resolve()), "inspected_files": other_files, "coverage": other_coverage,
            "findings": [asdict(f) for f in other],
            "claim": "parallel scan counts only; no finding identity or chronological migration inferred",
        }
    observed = inventory(sdk, arch) if sdk is not None else None
    groups = []
    for rule in RULES:
        count = counts[rule.id]
        other_count = other_counts[rule.id] if other_counts is not None else None
        if not count and not other_count:
            continue
        group = {
            "rule_id": rule.id, "count": count, "severity": rule.severity,
            "remediation": rule.remediation, "source": rule.source,
            "project_evidence": "static_candidate",
        }
        if other_count is not None:
            group["comparison_count"] = other_count
        if rule.id in ARTIFACTS and observed is not None:
            old, new = ARTIFACTS[rule.id]
            group["inventory_context"] = {
                "legacy_examples": {n: observed["artifacts"][n] for n in old},
                "replacement_examples": {n: observed["artifacts"][n] for n in new},
                "claim": "fixed named examples, not a match for every finding or a safe substitution",
            }
        if rule.id in FIXTURE_EVIDENCE:
            result, receipt = FIXTURE_EVIDENCE[rule.id]
            group["historical_fixture_context"] = {
                "observation": result, "receipt": receipt, "sdk": "8.0.6 x86_64",
                "applies_to_scanned_project": False,
            }
        groups.append(group)
    return {
        "schema": "qnx-migration-report/v0.1",
        "source": {"path": str(root.resolve()), "inspected_files": files, "coverage": coverage,
                   "findings": [asdict(f) for f in findings]},
        "comparison": comparison, "sdk_inventory": observed,
        "rule_groups": groups, "limitations": LIMITS,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path)
    p.add_argument("--sdk", type=Path)
    p.add_argument("--arch", choices=["x86_64", "aarch64le"], default="x86_64")
    p.add_argument("--compare", type=Path)
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)
    try:
        report = make_report(args.path, args.sdk, args.arch, args.compare)
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        s = report["source"]
        print(f"QNX Migration Proof | {s['inspected_files']} inspected files | {len(s['findings'])} candidates")
        for group in report["rule_groups"]:
            count = str(group["count"])
            if "comparison_count" in group:
                count += f" -> {group['comparison_count']}"
            print(f"{group['rule_id']}: {count} | {group['remediation']}")
            for key, artifacts in group.get("inventory_context", {}).items():
                if isinstance(artifacts, dict):
                    print("  " + key + ": " + ", ".join(f"{n}={v['status']}" for n, v in artifacts.items()))
            if "historical_fixture_context" in group:
                print("  historical fixture: " + group["historical_fixture_context"]["observation"])
        print("Limitations: " + " ".join(report["limitations"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
