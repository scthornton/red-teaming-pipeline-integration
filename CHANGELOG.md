# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Invalid ASR, missing category evidence, unknown category names, and partial
  scans now fail the gate instead of allowing a passing result.
- COMPLIANCE group guardrails include successful framework techniques.
- Expired OAuth tokens refresh on 401; safe reads retry transient failures.
  Ambiguous scan-create requests are not replayed.
- Nightly failures remain failures after artifact upload and notification.
- Workflow inputs pass through environment variables instead of shell source.
- Empty numeric environment defaults no longer crash argument parsing.
- Target discovery follows all pages and detects repeated or incomplete pages.

### Added
- Result artifacts with scan identity, policy, status, verdict, and timestamps.
- Local HTTP regression tests and a push/PR test workflow.
- A reusable deployment scan example requiring matching commit evidence.
- Pinned dependencies, pinned Actions, limited workflow permissions, and
  Dependabot update checks.

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
