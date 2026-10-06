# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-06

Validated against a live AIRS tenant on 2026-10-06. See docs/EVIDENCE.md.

### Fixed
- The default STATIC scan was rejected with HTTP 400 because it requested
  MULTI_TURN, which the attack catalog now marks inactive. The default scope is
  now the subcategories SCM preselects, and inactive ones are rejected up front.
- HTTP errors now show the server's reason, not just the status code.
- A report with no executed attacks, goals, or streams is an ERROR, not a PASS.
  A category counts as tested only if attacks against it actually ran.
- A scan that did not complete wrote the full job record to the artifact,
  including the target's system prompt. It now writes a short job summary.
- Invalid ASR, missing category evidence, unknown category names, and partial
  scans fail the gate.
- Expired tokens refresh on 401 or 403. Reads retry transient failures. Scan
  creation is never replayed, and a 5xx on creation is reported as an unknown
  outcome.
- Nightly failures stay failures after artifact upload and notification, and
  `ci_report.py enforce` only accepts a PASS from the current run.
- Workflow inputs reach the scanner as environment variables, not shell text.
- Target discovery follows every page.

### Added
- `--scan-uuid` evaluates an existing scan without starting a new one. The
  manual workflow exposes it as `scan_uuid`.
- `--stream-breadth` and `--stream-depth` for DYNAMIC scans (defaults 6 and 10).
- `--version` and a `scanner_version` field in the result file.
- The example workflows check out the scanner at a pinned release, so they work
  when copied into another repository.
- Time budgets sized for a full library run (60 to 90 minutes measured).
- Pinned dependencies and Actions, Dependabot, and a test workflow with
  actionlint.

## [0.1.0] - 2026-06-02

Initial release. GitHub Actions CI/CD pipeline for automated AI Red Teaming with
Palo Alto Networks Prisma AIRS, validated end to end against a live tenant.

### Added
- `redteam_scan.py` orchestrator: OAuth2 (client_credentials) -> create scan ->
  poll to terminal -> fetch report -> evaluate policy -> exit code.
- Policy gate on Attack Success Rate ceiling (`--max-asr-percent`) and protected
  category guardrails (`--fail-on-categories`).
- `--list-targets` and `--list-categories` discovery modes.
- `--categories` to scope a STATIC scan (default: full attack library).
- Main `workflow_dispatch` workflow plus PR-triggered and nightly examples.
- Pytest suite (43 tests) covering ASR conversion, category extraction, scan
  body, report routing, and polling.
- Known-good STATIC report fixture under `fixtures/`.

### Verified against `@cdot65/prisma-airs-sdk` 0.11.0 (and a live tenant)
- Two base URLs share one OAuth token: a **data plane** (scans, reports,
  categories) and a **management plane** (targets).
- Scan-create body is `{name, target:{uuid}, job_type, job_metadata}`;
  `job_type` is `STATIC` or `DYNAMIC`. STATIC `job_metadata.categories` must be
  a non-empty `{CATEGORY_ID: [SUBCATEGORY_IDS]}` map (an empty `{}` is rejected
  with HTTP 422).
- Report endpoints are `/v1/report/static/{job}/report` and
  `/v1/report/dynamic/{job}/report`, routed by job type.
- `asr` is already a percent (0..100) in both STATIC and DYNAMIC report bodies
  and in job state (verified: 47 successful / 4302 attacks reports asr 1.09).
- Category vocabulary is `SECURITY` / `SAFETY` / `BRAND` / `COMPLIANCE` groups
  with subcategory ids (e.g. `PROMPT_INJECTION`, `JAILBREAK`). There is no `DLP`
  category.
- Terminal job statuses: `COMPLETED`, `PARTIALLY_COMPLETE`, `FAILED`, `ABORTED`.
