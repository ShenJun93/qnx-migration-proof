"""Create and replay a read-only, unsigned QNX migration evidence receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from qnx_migration_audit import MAX_FILE_BYTES, candidate_files
from qnx_migration_report import make_report

SCHEMA = "qnx-migration-receipt/v0.1"
TOOL_FILES = (
    "qnx_migration_audit.py", "qnx_migration_report.py",
    "qnx_evidence_receipt.py", "docs/BH0354_COMPILER_MIGRATION_EVIDENCE.md",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path):
    with path.open("rb") as stream:
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
        return h.hexdigest()


def source_manifest(root):
    """Match the scanner's recognized file scope, expose its unreadable/oversize skips."""
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    entries = []
    for p, relative, scope in candidate_files(root):
        entry = {"path": relative, "scope": scope}
        try:
            size = p.stat().st_size
            entry["bytes"] = size
            if size > MAX_FILE_BYTES:
                entry["status"] = "oversize_skipped"
            else:
                with p.open("rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) != size:
                    raise ValueError("Source changed during manifest capture")
                entry["sha256"] = hashlib.sha256(data).hexdigest()
                try:
                    data.decode("utf-8")
                except UnicodeError:
                    entry["status"] = "non_utf8_skipped"
                else:
                    entry["status"] = "readable"
        except OSError:
            entry["status"] = "unreadable"
        entries.append(entry)
    return sorted(entries, key=lambda e: e["path"])


def tool_manifest():
    base = Path(__file__).resolve().parent
    return {name: file_hash(base / name) for name in TOOL_FILES}


def build_payload(source, sdk=None, arch="x86_64", compare=None):
    before = source_manifest(source)
    comparison = source_manifest(compare) if compare is not None else None
    tools = tool_manifest()
    report = make_report(source, sdk, arch, compare)
    # No absolute source paths in portable receipts.
    report["source"].pop("path")
    if report["comparison"] is not None:
        report["comparison"].pop("path")
    observed = report["sdk_inventory"]
    if observed is not None:
        target = Path(observed.pop("target_root"))
        for info in observed["artifacts"].values():
            info["sha256_by_path"] = {p: file_hash(target / p) for p in info["paths"]}
        # Preserve the incomplete status, without leaking absolute error paths.
        observed["error_count"] = len(observed.pop("errors"))
    if (before != source_manifest(source)
            or comparison != (source_manifest(compare) if compare is not None else None)
            or tools != tool_manifest()):
        raise ValueError("Inputs changed during receipt generation; retry on stable sources")
    if sum(e["status"] == "readable" for e in before) != report["source"]["inspected_files"]:
        raise ValueError("Source manifest/scan count mismatch")
    if comparison is not None and sum(e["status"] == "readable" for e in comparison) != report["comparison"]["inspected_files"]:
        raise ValueError("Comparison manifest/scan count mismatch")
    return {
        "schema": SCHEMA, "tool_files": tools,
        "source_manifest": before, "comparison_manifest": comparison,
        "report": report,
        "limitations": [
            "Unsigned content digest: not proof of author, timestamp or trusted execution.",
            "Use an independently retained digest to detect replacement of both payload and digest.",
            "Replay compares scoped inputs and observations, not a full repository or SDK snapshot.",
            "Manifests bracket scanning; no atomic snapshot or protection against concurrent change and reversion.",
            "Oversize/unreadable files and excluded paths are not fully hashed.",
            "SDK hashes cover only present named artifact examples; no runtime or build certification.",
        ],
    }


def create_receipt(source, sdk=None, arch="x86_64", compare=None):
    payload = build_payload(source, sdk, arch, compare)
    return {"payload": payload, "sha256": digest(payload)}


def verify_receipt(receipt, source, sdk=None, arch="x86_64", compare=None, expected=None):
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "sha256"}:
        return False, "invalid receipt envelope"
    payload = receipt["payload"]
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        return False, "unsupported schema"
    actual = digest(payload)
    if actual != receipt["sha256"]:
        return False, "content digest mismatch"
    if expected is not None and actual != expected.lower():
        return False, "independent digest mismatch"
    fresh = build_payload(source, sdk, arch, compare)
    if fresh != payload:
        changed = sorted(k for k in set(fresh) | set(payload) if fresh.get(k) != payload.get(k))
        return False, "replay mismatch: " + ", ".join(changed)
    return True, "scoped replay matches; unsigned receipt, not runtime proof"


def unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON key: " + key)
        out[key] = value
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["create", "verify"])
    p.add_argument("source", type=Path)
    p.add_argument("--sdk", type=Path)
    p.add_argument("--arch", choices=["x86_64", "aarch64le"], default="x86_64")
    p.add_argument("--compare", type=Path)
    p.add_argument("--receipt", type=Path)
    p.add_argument("--expected-sha256")
    args = p.parse_args(argv)
    try:
        if args.action == "create":
            if args.receipt or args.expected_sha256:
                p.error("--receipt and --expected-sha256 are for verify")
            print(json.dumps(create_receipt(args.source, args.sdk, args.arch, args.compare), indent=2))
            return 0
        if args.receipt is None:
            p.error("verify requires --receipt")
        receipt = json.loads(args.receipt.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_pairs)
        ok, message = verify_receipt(receipt, args.source, args.sdk, args.arch,
                                     args.compare, args.expected_sha256)
        print(("MATCH: " if ok else "MISMATCH: ") + message)
        return 0 if ok else 1
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        p.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
