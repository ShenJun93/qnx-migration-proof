"""Plan and review QNX migration work using a fresh scoped evidence receipt."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from qnx_evidence_receipt import create_receipt, digest, file_hash

# Checklists deliberately require human review. No command is run or patch applied.
CHECKS = {
    "QNX8-NET-001": (
        "Review io-sock startup arguments, permissions and module loading.",
        "Build the target image and verify network initialization on the intended target.",
        "runtime_and_image"),
    "QNX8-NET-002": (
        "Identify the real NIC or emulator device and select a supported devs driver.",
        "Verify hardware identity, driver availability and network traffic on target.",
        "hardware_and_runtime"),
    "QNX8-NET-003": (
        "Review DHCP configuration, lease paths, resolver hooks and interface names.",
        "Verify DHCP lease acquisition, renewal, DNS and reconnect on target.",
        "runtime"),
    "QNX8-CRYPTO-001": (
        "Review OpenSSL 3 qcrypto plugin configuration and consumers.",
        "Build the image and verify cryptographic initialization and application behavior.",
        "image_and_runtime"),
    "QNX8-BLD-001": (
        "Review the obsolete data=c attribute and intended section placement.",
        "Rebuild the image with mkifs and inspect the resulting layout.",
        "image"),
    "QNX8-SRC-001": (
        "Review interrupt event handling, mask/unmask, wait and detach lifecycle.",
        "Compile and link, then verify interrupt delivery on the intended target.",
        "hardware_and_runtime"),
    "QNX8-SRC-002": (
        "Review identity APIs, secpol header, linker flags and required permissions.",
        "Compile and link the actual driver; verify identity and permission behavior.",
        "build_and_runtime"),
    "QNX8-SRC-003": (
        "Review I2C request layout, slave addressing, command and buffer sizes.",
        "Compile and link; test actual device transactions and error handling.",
        "hardware_and_runtime"),
    "QNX8-CC-001": (
        "Review and remove the obsolete -auxbase option from affected build settings.",
        "Rebuild the actual project and check code coverage settings if applicable.",
        "build"),
}


def literal_reference(name, excerpt):
    # Exact basename token in the visible excerpt, not dependency resolution.
    return bool(re.search(r"(?<![A-Za-z0-9_.-])" + re.escape(name)
                          + r"(?![A-Za-z0-9_.-])", excerpt))


def make_plan(source, sdk=None, arch="x86_64", compare=None):
    receipt = create_receipt(source, sdk, arch, compare)
    payload = receipt["payload"]
    report = payload["report"]
    manifest = {row["path"]: row for row in payload["source_manifest"]}
    comparison_manifest = payload["comparison_manifest"]
    source_skips = sum(row["status"] != "readable" for row in manifest.values())
    comparison_skips = (sum(row["status"] != "readable" for row in comparison_manifest)
                        if comparison_manifest is not None else None)
    tasks = []
    for group in report["rule_groups"]:
        rule = group["rule_id"]
        action, validation, gate = CHECKS[rule]
        locations = []
        for f in report["source"]["findings"]:
            if f["rule_id"] != rule:
                continue
            exact = []
            for name, observation in group.get("inventory_context", {}).get("legacy_examples", {}).items():
                if literal_reference(name, f["excerpt"]):
                    exact.append({"literal": name, "sdk_observation": observation,
                                  "claim": "literal in excerpt; may be a path or config reference, not executable use"})
            locations.append({
                "path": f["path"], "line": f["line"], "column": f["column"],
                "source_sha256": manifest[f["path"]].get("sha256"),
                "excerpt": f["excerpt"], "literal_inventory_context": exact,
            })
        count = group["count"]
        other = group.get("comparison_count")
        if other is None:
            review = "baseline_only"
        elif not count:
            review = "comparison_only_candidate"
        elif other == 0 and not comparison_skips:
            review = "not_observed_in_comparison"
        elif other == 0:
            review = "comparison_incomplete"
        else:
            review = "candidates_remain_in_comparison"
        tasks.append({
            "rule_id": rule, "severity": group["severity"], "candidate_count": count,
            "comparison_count": other, "review_state": review,
            "locations": locations, "action": action, "validation": validation,
            "required_validation": gate, "validation_state": "not_run",
            "source": group["source"], "automatic_edit": False,
            "historical_fixture_context": group.get("historical_fixture_context"),
            "replacement_examples": group.get("inventory_context", {}).get("replacement_examples", {}),
        })
    plan = {
        "schema": "qnx-migration-plan/v0.1",
        "receipt_sha256": receipt["sha256"],
        "planner_sha256": file_hash(Path(__file__)),
        "source_skips": source_skips, "comparison_skips": comparison_skips,
        "tasks": tasks,
        "limitations": [
            "Review tasks are grouped by rule, not independent defects.",
            "Comparison counts are not issue lineage, proof of repair or runtime compatibility.",
            "All actual project validation is not_run; historical fixtures are context only.",
            "No edit, build, deployment or automatic driver substitution is performed.",
            "Literal inventory context matches exact visible tokens, not full dependency resolution.",
            "Excluded scanner paths and unreadable files limit coverage.",
        ],
    }
    return {"plan": plan, "plan_sha256": digest(plan), "receipt": receipt}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("--sdk", type=Path)
    p.add_argument("--arch", choices=["x86_64", "aarch64le"], default="x86_64")
    p.add_argument("--compare", type=Path)
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)
    try:
        bundle = make_plan(args.source, args.sdk, args.arch, args.compare)
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    if args.format == "json":
        print(json.dumps(bundle, indent=2))
    else:
        plan = bundle["plan"]
        print("QNX Migration Proof | remediation review")
        for task in plan["tasks"]:
            print(f"{task['rule_id']} | {task['candidate_count']} -> {task['comparison_count']} | {task['review_state']}")
            print("  Action: " + task["action"])
            print("  Validate: " + task["validation"] + " [not_run]")
        print("Receipt: " + plan["receipt_sha256"])
        print("Limitations: " + " ".join(plan["limitations"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
