# Prisma AIRS Red Teaming CI/CD Pipeline

Run Prisma AIRS Red Teaming against a registered target and evaluate the results as a CI gate. The scanner supports STATIC attack-library scans and DYNAMIC agent scans.

The gate returns success only after a completed scan has a valid ASR within policy. STATIC scans can also fail on successful attacks in protected categories. Invalid reports, missing category evidence, partial completion, and configuration errors fail the gate.

This project scans an existing deployed application. It does not deploy the application or independently discover which source revision it serves.

## Quick start

1. Register and validate a target in Strata Cloud Manager. For a private target, configure the required Network Channel.
2. Set the Actions secret `PRISMA_AIRS_CLIENT_SECRET` and repository variables `PRISMA_AIRS_CLIENT_ID` and `PRISMA_AIRS_TSG_ID`.
3. Open **Actions > Prisma AIRS Red Teaming Scan > Run workflow** and enter the target UUID.
4. Review the job summary and the `red-team-scan-report` artifact.

The manual workflow uses a 5% ASR ceiling by default. Choose policy thresholds for your application and risk tolerance. A passing scan is evidence for the tested attack scope, not proof that the application is secure.

## Local usage

Python 3.12 is the tested runtime. Install into a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

export PRISMA_AIRS_CLIENT_ID='your-client-id'
export PRISMA_AIRS_CLIENT_SECRET='your-client-secret'
export PRISMA_AIRS_TSG_ID='your-tsg-id'

python redteam_scan.py --list-targets
python redteam_scan.py --list-categories

python redteam_scan.py \
  --target-uuid 'your-target-uuid' \
  --scan-type STATIC \
  --max-asr-percent 5 \
  --fail-on-categories PROMPT_INJECTION,JAILBREAK
```

Runtime dependencies and their transitive dependencies are pinned in `requirements.txt`. Dependabot checks dependency and GitHub Actions updates weekly.

## Policy behavior

| Condition | Exit code | Result |
| --- | --- | --- |
| Completed scan, valid evidence, within policy | `0` | `PASS` |
| ASR above the ceiling or a protected category succeeded | `1` | `FAIL` |
| Invalid or missing evidence, partial scan, configuration, API, or output error | `2` | `ERROR` |

ASR is a percentage, not a fraction: `1.09` means 1.09%. Both the measured ASR and threshold must be finite numbers from 0 to 100. Equality with the threshold passes.

Category names are case-insensitive; spaces are normalized to underscores. Use the vocabulary returned by `--list-categories`. Supported group names are `SECURITY`, `SAFETY`, `BRAND`, and `COMPLIANCE`. Framework and subcategory IDs are accepted when present in the selected scan vocabulary.

Every protected category must be included in the scan scope and have measured results in the report. Unknown names, missing success counts, and categories outside the selected scope are errors. For example, scanning only `JAILBREAK` while protecting `PROMPT_INJECTION` is rejected before scan creation.

DYNAMIC scans do not provide the STATIC category breakdown. Combining DYNAMIC with either `--categories` or `--fail-on-categories` is rejected. CUSTOM scans are not supported by this integration.

`PARTIALLY_COMPLETE` is an error, even if its available results look clean. The artifact preserves the terminal job state for investigation.

## CLI configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `--target-uuid` | Required for scans | Existing registered AIRS target |
| `--scan-type` | `STATIC` | `STATIC`, `DYNAMIC`, or legacy `ATTACK_LIBRARY` alias |
| `--scan-name` | Generated from scan type | Human-readable job name |
| `--categories` | All available categories | STATIC groups or subcategory IDs, comma-separated |
| `--max-asr-percent` | `5.0` | Maximum allowed ASR |
| `--fail-on-categories` | Empty | STATIC categories that fail on any success |
| `--poll-interval` | `30` seconds | Positive interval between polls |
| `--max-wait-minutes` | `60` | Positive polling budget |
| `--report-out` | `red_team_report.json` | Raw report or unsuccessful terminal state |
| `--result-out` | `red_team_result.json` | Scan identity, policy, status, and verdict |
| `--expected-sha` | Unset | Full commit SHA that must be deployed |
| `--deployed-sha` | Unset | Full commit SHA verified by a trusted deployment job |

The two SHA options must be supplied together and match. They check the caller's deployment evidence; they do not query the application to verify its revision.

Environment defaults are also supported: `MAX_ASR_PERCENT`, `FAIL_ON_CATEGORIES`, `SCAN_CATEGORIES`, `POLL_INTERVAL_SECONDS`, and `MAX_WAIT_MINUTES`. CLI options take precedence. Empty numeric environment variables use the built-in defaults.

Optional endpoint variables:

| Variable | Default |
| --- | --- |
| `PRISMA_AIRS_TOKEN_ENDPOINT` | `https://auth.apps.paloaltonetworks.com/oauth2/access_token` |
| `PRISMA_AIRS_RED_TEAM_DATA_ENDPOINT` | `https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane` |
| `PRISMA_AIRS_RED_TEAM_MGMT_ENDPOINT` | `https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane` |

`TSG_ID` is accepted as a fallback for `PRISMA_AIRS_TSG_ID`. Endpoint overrides are trusted configuration; use the correct HTTPS endpoints for your region.

## Workflows

### Manual and scheduled scans

The installed workflow is manual by default. To enable its commented schedule, first configure `RED_TEAM_TARGET_UUID`. Scheduled runs use STATIC, all categories, a 5% ASR ceiling, and a 60-minute polling budget. The manual workflow limits its polling budget to 75 minutes so the 90-minute job has time for setup and artifacts.

For a stricter nightly policy, copy [the nightly example](examples/example-nightly-workflow.yml) into `.github/workflows/`, configure `PROD_TARGET_UUID`, and optionally set the `SLACK_WEBHOOK_URL` secret. The workflow preserves scan failures after upload and notification. Missing reports do not prevent notification; a missing webhook simply skips it.

### Scanning a PR deployment

[The deployment example](examples/example-pr-workflow.yml) is a reusable workflow, not a standalone `pull_request` trigger. Copy it into `.github/workflows/` and call it after your trusted deployment job:

```yaml
red_team:
  needs: deploy
  uses: ./.github/workflows/example-pr-workflow.yml
  with:
    target_uuid: ${{ needs.deploy.outputs.airs_target_uuid }}
    expected_sha: ${{ needs.deploy.outputs.requested_sha }}
    deployed_sha: ${{ needs.deploy.outputs.verified_running_sha }}
  secrets:
    PRISMA_AIRS_CLIENT_SECRET: ${{ secrets.PRISMA_AIRS_CLIENT_SECRET }}
```

Your deployment job must read back the running application's revision and emit `verified_running_sha`. Do not fill that output by copying the requested SHA. Use an isolated target per PR, or keep the complete deployment and scan sequence serialized so another deployment cannot replace the target mid-scan. The scanner's concurrency group serializes scans only.

The example checks out the trusted scanner from `main`. Keep secrets out of untrusted PR code and do not use `pull_request_target` to run PR code with credentials. Adapt the trusted branch name if your repository uses a different default branch.

These workflows write job summaries. They do not post PR comments.

## Results and recovery

`red_team_report.json` contains the raw API report, or the final state for an unsuccessful scan. `red_team_result.json` records the target and scan UUIDs, selected categories, configured policy, terminal status, verdict, exit code, timestamps, and available workflow/deployment identifiers.

The result is checkpointed immediately after scan creation. If monitoring fails, use the recorded UUID to inspect the existing scan in SCM. Starting the CLI again creates a new scan; there is no resume command. A CI timeout or cancellation does not cancel the remote scan.

Expired tokens are refreshed once after a 401 on each API operation. Safe reads retry temporary connection failures, timeouts, HTTP 429, and selected 5xx responses, with at most three failed attempts. Retry-After is honored within the polling budget; waits above two minutes fail instead of retrying early. Scan creation is not retried after an ambiguous transport failure or 5xx response. Check SCM before submitting another scan.

Artifacts are retained for 14 days in the supplied workflows. Reports may contain sensitive security findings; choose repository access and retention accordingly. New scans remove an older report at the configured output path, preventing stale evidence from being uploaded after a failure. Argument parsing failures can occur before a result artifact is written.

## Development and validation

```bash
python -m pip install -r requirements-dev.txt
python -m pip check
python -m pytest -q
python -m pytest --cov=redteam_scan --cov=ci_report --cov-branch
```

The Tests workflow runs on pushes to `main` and on PRs. Tests cover policy validation, local HTTP scan lifecycles, token refresh, retry boundaries, result artifacts, shell input handling, and nightly failure propagation. They use dummy credentials and mocked notifications.

[The evidence record](docs/EVIDENCE.md) preserves the original June 2026 live run and explains the later offline regression checks. The recent fixes still need validation against your designated live target and deployment system.

## Companion and license

[model-security-pipeline-integration](https://github.com/scthornton/model-security-pipeline-integration) covers model artifact scanning. This repository covers behavioral testing of deployed targets.

MIT. See [SECURITY.md](SECURITY.md) for reporting security issues.
