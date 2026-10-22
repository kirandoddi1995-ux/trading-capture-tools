# Inactive, separately audited capture release candidate

This distribution does NOT authorize capture. It does not clear the application's
Streamlit/Pillow audit. No producer trading/rule/window/clock/state/eligibility
change is intended. Source provenance and exact transformations are in
CAPTURE_DISTRIBUTION.json. Producer origin is frozen 125153…; daily controller
origin is approved public 563665…; only certifi moves to 2026.10.19.

Runtime: Python 3.13.9, all 18 distributions pinned; only published hashed wheels.
requirements-capture.lock is the COMPLETE runtime, not a constraint overlay.
requirements-test.lock includes the complete separate test/audit tool graph.
The four plain requirements/constraint files exist for unchanged producer
fingerprinting and diagnostics; installation uses the hashed lock only.

## NOT ready for owner execution

Mandatory release gates: complete source review, whole runtime and test audits,
Windows and Linux synthetic suites, exact-final-SHA hosted quality and CodeQL
(including code-scanning results), owner-only merge, matching merged-SHA clean
tools/capsule, native disabled-task binding and notification acceptance.
Any pending/failed/unknown gate means NO_GO. A clean test result is not custody,
an actual clock check, or permission to activate. No date is automatically GO.

The controller requires -ReviewedCommit with the owner's externally accepted
full merged SHA. Both tools and capsule must match that exact commit and complete
manifest BEFORE installs/imports. No embedded self-SHA, no in-place runtime upgrade,
no old capsule fallback. New capsules use reviewed_capture_YYYYMMDD; date-pinned
task names and private roots remain unchanged. Existing tasks are never replaced
with -Force: old bindings block and require read-only reconciliation. Do NOT delete
or edit them to make this pass. No cleanup/reset is authorized. Both native task
arguments and the read-only host checker bind that exact SHA. Scheduled polls,
calendar/prepared/health checks and manual product commands share the -I/-S guarded
dispatcher. Source admission reads committed blobs in batches, rejects a source
validation exceeding its ten-second elapsed budget, and bounds directory counts;
runtime metadata and bootstrap are separately bounded. The dispatcher refuses
product dispatch after fifteen seconds of admission. These are checked elapsed
budgets, NOT a claim that an unresponsive OS/filesystem can be preempted. Existing
two-minute task and poll windows are unchanged. Actual target cold/warm timing
with reserve for producer work remains a native owner acceptance gate.

A bootstrap/admission or unknown-dispatch exception returns distinct exit3 so the
task wrapper attempts a separate local alert even before product notifications
are available. That is routing logic, not proof the owner saw a production alert.
The legacy installer is retained only as .txt historical review input for an
unchanged regression; it is not the route for installing this release.

Local source-only preview: python -I -S -B standalone_capture_contract.py
Source-only hash check: python -I -S -B standalone_capture_contract.py --check-files
Precommit: explicit Python 3.13.9, same script --check-index-base FULL_BOOTSTRAP_BASE
After commit: same script --verify-commit FULL_FINAL_SHA

The repository must contain ONLY the manifest and its listed files, ordinary
100644 Git modes, no credentials/private data. A fresh repository/base must be
recorded in a reviewed upload record before the owner uses the index checker.
Never upload the mixed working folder. No real native acceptance has occurred
merely because this candidate was exported. Active session/state is out of scope.
