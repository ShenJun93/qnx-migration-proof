# QNX 8 migration evidence lab: diagnose, rebuild, and verify

A hands-on Windows host tutorial for developers moving software and image configurations from QNX SDP 7.1 to 8.0.

## What you will learn

- Distinguish static migration hints from actual compiler and image-builder diagnostics.
- Reproduce a removed GCC option, an identity API header change, a deprecated interrupt API, an obsolete image attribute, and a missing legacy networking executable.
- Verify local evidence and recognize when a build does not establish runtime compatibility.

## Prerequisites

A trusted, legitimately licensed QNX SDP 8.0 installation on Windows with the x86_64 target, Python 3.10 or newer, and a checkout of this repository. The observed baseline is SDP 8.0.6 with GCC 12.2.0. No QNX 7.1 compiler, VM, board, third-party Python package or paid AI service is required. Results may differ by SDK release and installed packages.

Run the following commands in PowerShell from the repository root. Adjust the SDK location to your installation. Use a new output directory each time. Keep SDK-derived files local and follow your SDK license.

    $sdk = 'D:\QNX\qnx800'
    $lab = Join-Path $env:TEMP ('qnx-migration-lab-' + [guid]::NewGuid().ToString())
    python -m unittest discover -q
    python qnx_migration_lab.py run --sdk $sdk --output $lab

Stop if a command fails unexpectedly. The lab intentionally builds legacy cases that fail; the overall command succeeds only when expected observations match. It never executes target binaries or builds arbitrary user projects.

## Exercise 1 - Read the evidence, not only the exit code

Open the generated lab.json in your editor. Find the five cases in payload.cases and inspect before/after exit_code, stderr and findings.

| Case | Expected before | Expected after | Lesson |
|---|---|---|---|
| auxbase | Exit 1, unsupported option | Exit 0 | Compiler flag changes can block builds |
| ids | Exit 1 under strict warnings | Exit 0 | Review both header and linker settings |
| interrupt | Exit 0 | Exit 0 | Build success does not prove interrupt semantics |
| data | Exit 0 with warning | Exit 0 without warning | An obsolete attribute can be ignored by the builder |
| stack | Exit 1, missing host file | Exit 0 | Legacy networking packaging must change |

Question: Which cases actually fail before migration? Answer: auxbase, ids and stack. The data case is a warning; interrupt requires target-side validation. The image outputs are controlled, non-bootable examples.

## Exercise 2 - Inspect source and SDK context

    python qnx_migration_audit.py "$lab\images\stack\before" --format json
    python qnx_migration_audit.py "$lab\images\stack\after" --format json
    python qnx_migration_plan.py "$lab\images\stack\before" --compare "$lab\images\stack\after" --sdk $sdk

The scanner should identify QNX8-NET-001 in the baseline and not in the comparison. The plan asks for image and runtime checks. Find the legacy reference and the replacement in the two image.build files. A change in candidate count is not proof of a working network stack.

The lab uses original minimal fixtures, not actual third-party applications. The tool does not prescribe a universal driver substitution.

## Exercise 3 - Verify the recorded evidence

Copy the LAB_SHA256 value from the original run and retain it separately from the output directory. Replace the example placeholder below with that value.

    $pin = 'PASTE_THE_64_HEX_DIGEST_FROM_THE_RUN'
    python qnx_migration_lab.py verify --sdk $sdk --output $lab --expected-sha256 $pin

Expected: local build evidence hashes and scoped source/SDK replay match; no rebuild performed.

For a negative control, copy the output to a fresh directory and append text to the copied IFS file only.

    $copy = "$lab-tamper"
    Copy-Item -LiteralPath $lab -Destination $copy -Recurse
    [IO.File]::AppendAllText((Join-Path $copy 'images\stack\after\proof.ifs'), 'TAMPER')
    python qnx_migration_lab.py verify --sdk $sdk --output $copy --expected-sha256 $pin
    $LASTEXITCODE

Expected: local build evidence changed; exit 1. The original output remains intact. Do not use the altered image for any purpose.

## Exercise 4 - Review the result offline

    $page = Join-Path $env:TEMP ('qnx-review-' + [guid]::NewGuid().ToString() + '.html')
    python qnx_review_dashboard.py "$lab\images\stack\before" --compare "$lab\images\stack\after" --sdk $sdk --lab $lab --lab-sha256 $pin --output $page
    Invoke-Item -LiteralPath $page

Open the remediation group, then the separate controlled lab section. Observe the original diagnostic, the changed build result and the receipt digest. The scanned-project validation counter remains zero; lab evidence is not project certification. The HTML contains a snapshot and does not verify live.

## Troubleshooting and next steps

- SDK environment file missing: verify the installed SDK path and x86_64 target package.
- Unexpected compiler/image-builder result: inspect compiler-run.json and lab.json (if generated). Do not classify an unrelated compiler error as a successful migration demonstration.
- Digest mismatch: use the original retained digest and exact tool implementation, then check for changed inputs or outputs. Do not overwrite a failed receipt to make it pass.
- Need real hardware or runtime assurance: build the actual application with its normal build process and test on its intended QNX target. The tutorial deliberately stops short of that claim.

## Official reading

- QNX migration: https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/bsps.html
- Toolchain migration: https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/IDE.html
- mkifs: https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html

Evidence is unsigned, scoped and local. Do not redistribute SDK-generated images or logs containing sensitive paths without review.
