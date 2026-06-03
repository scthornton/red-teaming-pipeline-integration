# Prisma AIRS Red Teaming CI/CD Pipeline

Production-ready GitHub Actions workflow for automated **AI Red Teaming** of LLM-backed targets (apps, agents, model endpoints) using Palo Alto Networks Prisma AIRS.

Companion to [`model-security-pipeline-integration`](https://github.com/scthornton/model-security-pipeline-integration), which covers the model-artifact side. This repo covers the runtime/behavioral side: take an already-registered Red Teaming target in SCM, run a scan against it on every PR (or nightly), and fail the pipeline if the target regresses past your policy.

## What This Does

Runs a Prisma AIRS Red Teaming scan against an existing target and enforces policy as a pipeline gate:

- **STATIC scan (attack library)**: a large fixed corpus of known adversarial prompts, organized into categories and subcategories (prompt injection, jailbreak, system-prompt leak, malware generation, safety/toxic content, brand, compliance). Fast, broad, repeatable; ideal for regression-testing every release. This is the default.
- **DYNAMIC scan (agent)**: an adversarial agent probes the target adaptively over multi-turn conversations, pursuing goals. Slower but deeper.

**Policy enforcement**: the pipeline fails if the measured Attack Success Rate exceeds your threshold, or if any successful attacks land in protected categories (e.g. `PROMPT_INJECTION`, `JAILBREAK`). The full report is uploaded as a workflow artifact; PR comments get the summary inline.

The canonical category vocabulary is four groups (`SECURITY`, `SAFETY`, `BRAND`, `COMPLIANCE`) with their subcategories. List the exact names from your tenant with `python redteam_scan.py --list-categories`. (There is no `DLP` category; the closest security subcategories are `SYSTEM_PROMPT_LEAK` and `TOOL_LEAK`.)

Note: category guardrails apply to STATIC scans only. DYNAMIC reports carry no category breakdown, so `--fail-on-categories` is a no-op there and the gate relies on ASR.

## Quick Start

### 1. Configure GitHub Secrets and Variables

**Required Secrets** (Settings → Secrets and variables → Actions → Secrets):

- `PRISMA_AIRS_CLIENT_SECRET` — your SCM service account OAuth2 client secret

**Required Variables** (Settings → Secrets and variables → Actions → Variables):

- `PRISMA_AIRS_CLIENT_ID` — your SCM service account client ID
- `PRISMA_AIRS_TSG_ID` — your Tenant Service Group ID

**Optional Variables** (only override if you're in a non-default region):

- `PRISMA_AIRS_RED_TEAM_DATA_ENDPOINT` — defaults to `https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane` (scans, reports, categories)
- `PRISMA_AIRS_RED_TEAM_MGMT_ENDPOINT` — defaults to `https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane` (targets)
- `PRISMA_AIRS_TOKEN_ENDPOINT` — defaults to `https://auth.apps.paloaltonetworks.com/oauth2/access_token`

Red Teaming uses two base URLs that share one OAuth token: a **data plane** for scan jobs, reports, and categories, and a **management plane** for targets. The defaults are correct for the US region.

### 2. Register a Target in SCM (one-time)

This pipeline scans an **existing** target. Create one in Strata Cloud Manager (AI Security → AI Red Teaming → Targets → New Target) and copy its UUID for the workflow input. The target can be a REST API endpoint, a Streaming endpoint, or an agentic application.

If your target is private (behind a corporate firewall or VPC), register a Network Channel first and bind the target to it.

### 3. Run the Workflow

1. Go to the **Actions** tab.
2. Select **"Prisma AIRS Red Teaming Scan"**.
3. Click **"Run workflow"** and fill in:
   - **Target UUID** (required) — from step 2. List your targets with `python redteam_scan.py --list-targets`.
   - **Scan type** (optional) — `STATIC` (default, attack library) or `DYNAMIC`.
   - **Max ASR percent** (optional) — pipeline fails if measured ASR exceeds this. Default: `5.0`.
   - **Fail on categories** (optional) — comma-separated list, e.g. `PROMPT_INJECTION,JAILBREAK`. If any successful attacks land here, the pipeline fails regardless of ASR. STATIC only.
   - **Max wait minutes** (optional) — how long to wait for the scan before timing out. Default: `60`.
4. Click **"Run workflow"**.

### 4. Review Results

- **Green check**: target stayed within policy.
- **Red X**: scan timed out, errored, or policy violated. Open the `red-team-scan-report` artifact for the full JSON report.
- **PR comments**: when triggered from a PR, the workflow posts the scan status and ASR as a PR comment.

## Configuration Reference

### Workflow Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `target_uuid` | Yes | — | UUID of an existing Red Teaming target in SCM. |
| `scan_type` | No | `STATIC` | Scan flavor: `STATIC` (attack library) or `DYNAMIC` (agent). |
| `max_asr_percent` | No | `5.0` | Attack Success Rate ceiling (percent). |
| `fail_on_categories` | No | (empty) | Category/subcategory names that fail the pipeline on any successful attack. STATIC only. |
| `max_wait_minutes` | No | `60` | Total wait budget for scan completion. |

### Environment Variables (Variables / Secrets)

| Variable | Default | Description |
|---|---|---|
| `PRISMA_AIRS_CLIENT_ID` | — | SCM service account client ID (Variable). |
| `PRISMA_AIRS_CLIENT_SECRET` | — | SCM service account client secret (**Secret**). |
| `PRISMA_AIRS_TSG_ID` | — | TSG ID (Variable). |
| `PRISMA_AIRS_RED_TEAM_DATA_ENDPOINT` | `https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane` | Data plane base URL (scans, reports, categories). |
| `PRISMA_AIRS_RED_TEAM_MGMT_ENDPOINT` | `https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane` | Management plane base URL (targets). |
| `PRISMA_AIRS_TOKEN_ENDPOINT` | `https://auth.apps.paloaltonetworks.com/oauth2/access_token` | OAuth2 token endpoint. |

## Policy Knobs

Two layered policies are evaluated against every report:

1. **ASR ceiling.** If measured Attack Success Rate exceeds `max_asr_percent`, the pipeline fails. Reasonable starting points:
   - Production (strict): `1.0` to `2.0`
   - Staging (balanced): `5.0`
   - Dev (loose): `15.0`

2. **Category guardrails.** If any successful attacks land in any of `fail_on_categories`, the pipeline fails regardless of overall ASR. Use this to enforce "we never want to ship a regression on prompt injection or system-prompt leakage" even if the overall score is acceptable. Names match category groups (`SECURITY`, `SAFETY`, `BRAND`, `COMPLIANCE`) or subcategory ids (`PROMPT_INJECTION`, `JAILBREAK`, `SYSTEM_PROMPT_LEAK`, ...). STATIC scans only.

Both policies trip an exit code of `1` (`EXIT_SECURITY_VIOLATION`), which fails the GitHub Actions step. Errors (auth, network, scan-creation failures) trip an exit code of `2` (`EXIT_ERROR`), which is also surfaced as a step failure but distinguishable in the logs.

## Running Locally

The same script powers local runs:

```bash
export PRISMA_AIRS_CLIENT_ID=<client-id>
export PRISMA_AIRS_CLIENT_SECRET=<client-secret>
export PRISMA_AIRS_TSG_ID=<tsg-id>

pip install requests tenacity

# Discover targets and the category vocabulary
python redteam_scan.py --list-targets
python redteam_scan.py --list-categories

# Run a STATIC (attack library) scan with policy
python redteam_scan.py \
  --target-uuid <target-uuid> \
  --scan-type STATIC \
  --max-asr-percent 5.0 \
  --fail-on-categories PROMPT_INJECTION,JAILBREAK
```

For a fast smoke test, narrow the scope with `--categories` (e.g. `--categories SECURITY` or `--categories PROMPT_INJECTION`); the default scans the full attack library.

The script writes `red_team_report.json` in the working directory. Exit codes: `0` pass, `1` policy violation, `2` error.

## Proof It Works

See [`docs/EVIDENCE.md`](docs/EVIDENCE.md) for a reproducible validation record:
unit tests, the live category vocabulary, the policy gate evaluated on a real
report, and a full end-to-end GitHub Actions run (with screenshot and the
uploaded report artifact).

[![Red Teaming Scan](https://github.com/scthornton/red-teaming-pipeline-integration/actions/workflows/red_teaming_scan.yml/badge.svg)](https://github.com/scthornton/red-teaming-pipeline-integration/actions/workflows/red_teaming_scan.yml)

## Companion Repos

- [`model-security-pipeline-integration`](https://github.com/scthornton/model-security-pipeline-integration) — model artifact scanning (pre-deployment).
- This repo — red teaming of deployed targets (runtime behavioral).

Use both together to cover the MLSecOps lifecycle: scan the artifact at build, red-team the running target at deploy.

## License

MIT.
