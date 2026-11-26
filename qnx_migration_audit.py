#!/usr/bin/env python3
"""Read-only QNX SDP 7.1 -> 8.0 migration risk scanner (host-side)."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

BSP_DOC = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/bsps.html"
IDE_DOC = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/IDE.html"
MAX_FILE_BYTES = 1024 * 1024
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}
CONFIG_SUFFIXES = {".bld", ".build", ".mk", ".cmake", ".sh", ".conf"}
CONFIG_NAMES = {"Makefile", "GNUmakefile", "CMakeLists.txt"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "__pycache__"}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    category: str
    expression: str
    description: str
    remediation: str
    source: str
    scope: str


RULES = (
    Rule("QNX8-NET-001", "high", "network", r"(?<![\w.-])io-pkt(?:-v[46](?:-hc|-lite)?)?(?![\w.-])",
         "Legacy io-pkt networking stack reference",
         "Migrate to io-sock and verify BSP network configuration", BSP_DOC, "config"),
    Rule("QNX8-NET-002", "high", "network", r"\bdevnp-[A-Za-z0-9_-]+",
         "Legacy devnp network driver reference",
         "Replace with a compatible devs-* io-sock driver; confirm device support", BSP_DOC, "config"),
    Rule("QNX8-NET-003", "high", "network", r"\b(?:dhclient|autoipd|rtsold)\b",
         "Discontinued network configuration utility",
         "Review dhcpcd-based configuration for QNX 8.0", BSP_DOC, "config"),
    Rule("QNX8-BLD-001", "high", "buildfile", r"\[\s*data\s*=\s*c\s*\]",
         "Unsupported [data=c] OS image buildfile attribute",
         "Remove the obsolete setting and rebuild with mkifs", BSP_DOC, "buildfile"),
    Rule("QNX8-CRYPTO-001", "medium", "crypto", r"\bqcrypto-openssl\.so\b",
         "Old OpenSSL qcrypto plugin filename",
         "Review replacement qcrypto-openssl-3.so and updated qcrypto tags", BSP_DOC, "config"),
    Rule("QNX8-SRC-001", "high", "interrupt", r"\bInterruptAttach\s*\(",
         "QNX 7 ISR attach API is not supported in QNX 8",
         "Use InterruptAttachEvent() and handle event/unmask lifecycle", BSP_DOC, "source"),
    Rule("QNX8-SRC-002", "medium", "security", r"^\s*#\s*include\s*<login\.h>",
         "Deprecated driver header for identity handling",
         "For BSP drivers using set_ids_from_arg, migrate to secpol/ids.h", BSP_DOC, "source"),
    Rule("QNX8-SRC-003", "medium", "i2c", r"\bDCMD_I2C_(?:SET_SLAVE_ADDR|MASTER_SEND|MASTER_RECV)\b",
         "Deprecated I2C devctl command",
         "Use DCMD_I2C_SEND/RECV and set slave in the request structure", BSP_DOC, "source"),
    Rule("QNX8-CC-001", "high", "toolchain", r"(?<![\w-])-auxbase\b",
         "Unsupported GCC 12 -auxbase flag",
         "Remove -auxbase and revalidate code coverage settings", IDE_DOC, "config"),
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    rule_id: str
    severity: str
    category: str
    excerpt: str
    description: str
    remediation: str
    source: str


def file_scope(path: Path) -> str | None:
    if path.suffix.lower() in SOURCE_SUFFIXES:
        return "source"
    # QNX BSPs also use an extensionless image buildfile named "build".
    if path.name.casefold() == "build":
        return "buildfile"
    if path.suffix.lower() in CONFIG_SUFFIXES or path.name in CONFIG_NAMES:
        return "buildfile" if path.suffix.lower() in {".build", ".bld"} else "config"
    return None


def mask_c_comments_and_strings(text: str) -> str:
    """Remove comments/literals, preserving newlines, columns and preprocessor directives."""
    out = []
    mode = "normal"
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if mode == "normal":
            if c == "/" and nxt == "*":
                out.extend("  ")
                i += 2
                mode = "block"
                continue
            if c == "/" and nxt == "/":
                out.extend("  ")
                i += 2
                mode = "line"
                continue
            if c == '"':
                out.append(" ")
                mode = "string"
            elif c == "'":
                out.append(" ")
                mode = "char"
            else:
                out.append(c)
        elif mode == "line":
            if c == "\n":
                out.append(c)
                mode = "normal"
            else:
                out.append(" ")
        elif mode == "block":
            if c == "*" and nxt == "/":
                out.extend("  ")
                i += 2
                mode = "normal"
                continue
            out.append("\n" if c == "\n" else " ")
        else:
            if c == "\\" and nxt:
                out.extend([" ", "\n" if nxt == "\n" else " "])
                i += 2
                continue
            if c == '"' and mode == "string":
                mode = "normal"
            if c == "'" and mode == "char":
                mode = "normal"
            out.append("\n" if c == "\n" else " ")
        i += 1
    return "".join(out)


def mask_config_line(line: str, path: Path) -> str:
    if line.lstrip().startswith("#"):
        return " " * len(line)
    # Inline comments in simple make/shell assignments. Do not guess mkifs grammar.
    if path.suffix.lower() not in {".mk", ".sh"} and path.name not in {"Makefile", "GNUmakefile"}:
        return line
    # Makefile recipes have shell semantics; leave ambiguous recipes alone.
    if line.startswith("\t") and path.suffix.lower() != ".sh":
        return line
    quote = None
    escaped = False
    for i, c in enumerate(line):
        if escaped:
            escaped = False
            continue
        if c == "\\" and quote != "'":
            escaped = True
        elif quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i-1].isspace()):
            return line[:i] + " " * (len(line)-i)
    return line


def candidate_files(root: Path):
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(str(root))
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file() and not p.is_symlink()
        and not (set(p.relative_to(root).parts[:-1]) & SKIP_DIRS)
    )
    return [(p, p.name if root.is_file() else p.relative_to(root).as_posix(), file_scope(p))
            for p in files if file_scope(p)]


def read_candidate(path: Path):
    """Return status and decoded content, with a bounded read."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return "oversize_skipped", None
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            return "oversize_skipped", None
        return "readable", raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeError:
        return "non_utf8_skipped", None
    except OSError:
        return "unreadable", None


def inspect_text(original: str, path: Path, relative: str, scope: str):
    lines = original.splitlines()
    masked = (mask_c_comments_and_strings(original).splitlines() if scope == "source"
              else [mask_config_line(line, path) for line in lines])
    results = []
    def add(rule, number, column):
        results.append(Finding(relative, number, column, rule.id, rule.severity, rule.category,
            lines[number-1].strip()[:220], rule.description, rule.remediation, rule.source))
    for rule in RULES:
        if rule.scope != scope and not (scope == "buildfile" and rule.scope == "config"):
            continue
        if rule.id == "QNX8-SRC-001":
            joined = "\n".join(masked)
            starts = [0] + [m.end() for m in re.finditer("\n", joined)]
            seen = set()
            for match in re.finditer(rule.expression, joined):
                number = bisect_right(starts, match.start())
                if number not in seen:
                    add(rule, number, match.start()-starts[number-1]+1)
                    seen.add(number)
            continue
        for number, line in enumerate(masked, 1):
            match = re.search(rule.expression, line, flags=re.IGNORECASE if scope != "source" else 0)
            if match:
                add(rule, number, match.start()+1)
    return sorted(results, key=lambda v: (v.path, v.line, v.column, v.rule_id))


def inspect_file(path: Path, relative: str, scope: str) -> list[Finding]:
    status, text = read_candidate(path)
    return inspect_text(text, path, relative, scope) if status == "readable" else []


def scan_detailed(root: Path):
    findings = []
    counts = Counter()
    for path, relative, scope in candidate_files(root):
        status, text = read_candidate(path)
        counts[status] += 1
        if status == "readable":
            findings.extend(inspect_text(text, path, relative, scope))
    coverage = {"recognized_files": sum(counts.values()), "inspected_files": counts["readable"],
                "skipped_files": sum(v for k,v in counts.items() if k != "readable"),
                "skip_reasons": {k:v for k,v in sorted(counts.items()) if k != "readable"}}
    return sorted(findings, key=lambda v: (v.path, v.line, v.column, v.rule_id)), coverage


def scan(root: Path) -> tuple[list[Finding], int]:
    findings, coverage = scan_detailed(root)
    return findings, coverage["inspected_files"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only QNX 7.1 -> 8.0 migration hints; NOT a compiler or certification")
    parser.add_argument("path", type=Path)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["high", "none"], default="none")
    args = parser.parse_args(argv)
    try:
        findings, coverage = scan_detailed(args.path)
        files = coverage["inspected_files"]
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(json.dumps({
            "schema": "qnx-migration-audit/v0.1",
            "claim": "documentation-backed static hints, not a QNX build or runtime verdict",
            "inspected_files": files,
            "coverage": coverage,
            "findings": [asdict(f) for f in findings],
        }, indent=2))
    else:
        for f in findings:
            print(f"{f.path}:{f.line}:{f.column}: {f.severity.upper()} {f.rule_id}: {f.description}")
            print(f"  migrate: {f.remediation}")
            print(f"  source: {f.source}")
        print(f"Inspected {files} source/config files; {len(findings)} potential migration issues; {coverage['skipped_files']} recognized files skipped")
    return 1 if args.fail_on == "high" and any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
