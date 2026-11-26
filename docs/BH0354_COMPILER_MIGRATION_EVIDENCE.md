# BH-0354 - QNX 8.0.6 compiler migration evidence (2026-11-26)

Windows host, owner-provisioned noncommercial QNX SDP 8.0.6, GCC 12.2.0, target gcc_ntox86_64. Scanner base commit 1c5e0e0. Original author-created minimal synthetic probes, not real migrated 7.1 applications. No target code executed.

| Rule | Before build | After build | Evidence class |
| --- | --- | --- | --- |
| QNX8-CC-001 | exit 1, unrecognized -auxbase | exit 0, same C source | compiler-confirmed on fixture |
| QNX8-SRC-002 | exit 1, implicit set_ids_from_arg under -Werror | exit 0, secpol/ids.h and -lsecpol | strict compiler-confirmed on fixture |
| QNX8-SRC-001 | exit 0 | exit 0, event API | documented migration risk; runtime unverified |

All three before fixtures matched their expected scanner rule, all three after fixtures had zero findings. Both interrupt variants compiled and linked; a clean build does NOT prove API semantics or interrupt lifecycle correctness. The original header login.h still exists. This is not evidence of a missing header. No actual 7.1 compiler was used; no precision/recall claim or BSP migration certification.

Reproduce on Windows with installed SDK:

    python qnx_migration_proof.py --sdk D:/QNX/qnx800 --output D:/QNX/qa-new

The output must be a new directory. Script only builds controlled fixtures; never executes target binaries or arbitrary scanned project build commands. Nonzero exit if expected observations differ. The observed results are tied to this SDK; version differences are not automatically failures of QNX.

Two independent executions using the original probe and the repository replay script produced matching six case/stage exit codes, source hashes and four output binary hashes. Existing scanner tests: 28/28 PASS.

Raw evidence retained locally; reproduce with the command above.

Observed successful output SHA256:
- auxbase after: 4ce71d9f5da36d5bd0277bbfbf794745dae77164889910c9b41c85ff6c2f20d4
- ids after: ac4039f5137fd6b9f739f6ef87078f6e5ea2b77d52121b95026300145a065460
- interrupt before: 300501d71b6f5959fb9fe0eb5b8a9de40355599b3ddb28a3b1fb3bef17e1d894
- interrupt after: cb9a2b042bfa6d14f9ee37c37280559ee742c321c8b8baa2ff5002912115bafe

References:
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/IDE.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.migration/topic/bsps.html

Next gate: license-safe real source before/after pair and issue-level labels. No VM installation required for the current host-tool gate.
