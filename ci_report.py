#!/usr/bin/env python3
"""Summarize scan results and notify without requiring a report to exist."""
import argparse
import json
import math
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def read_result(path):
    try:
        result = json.loads(Path(path).read_text())
        if isinstance(result, dict):
            return result
    except (OSError, ValueError):
        pass
    return {"verdict": "ERROR", "status": "NO_RESULT", "exit_code": 2}


def text(value):
    return str(value if value is not None else "unknown").replace("\n", " ").replace("\r", " ").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def policy_text(result):
    policy = result.get("policy") if isinstance(result.get("policy"), dict) else {}
    protected = policy.get("fail_on_categories")
    if isinstance(protected, list):
        protected = ", ".join(str(name) for name in protected) or "none"
    return policy.get("max_asr_percent"), protected


def summary(result):
    max_asr, protected = policy_text(result)
    lines = [
        "### Prisma AIRS Red Teaming",
        "",
        f"- Verdict: `{text(result.get('verdict', 'ERROR'))}`",
        f"- Scan status: `{text(result.get('status', 'UNKNOWN'))}`",
        f"- ASR: `{text(result.get('asr_percent'))}%`",
        f"- Policy: max ASR `{text(max_asr)}%`, protected categories `{text(protected)}`",
    ]
    if result.get("total_goals") is not None:
        policy = result.get("policy") if isinstance(result.get("policy"), dict) else {}
        limit = policy.get("max_goals_achieved")
        limit = "not checked" if limit is None else f"limit {text(limit)}"
        lines.append(f"- Goals achieved: `{text(result.get('goals_achieved'))}` of `{text(result['total_goals'])}` ({limit})")
    lines += [
        f"- Target: `{text(result.get('target_uuid'))}`",
        f"- Scan: `{text(result.get('scan_uuid'))}`",
    ]
    if result.get("error"):
        lines.append(f"- Error: `{text(result['error'])}`")
    if result.get("verdict") not in ("PASS", "FAIL") and result.get("scan_uuid"):
        lines += [
            "",
            "The remote scan may still be running. Check it in SCM, or re-run with "
            f"`--scan-uuid {text(result['scan_uuid'])}` to evaluate it without starting a new scan.",
        ]
    return "\n".join(lines + [""])


def enforce(result, scan_outcome):
    exit_code, asr, scan_uuid = result.get("exit_code"), result.get("asr_percent"), result.get("scan_uuid")
    # A result from another run (stale artifact, wrong download) must not pass.
    same_run = "GITHUB_RUN_ID" not in os.environ or result.get("run_id") == os.environ["GITHUB_RUN_ID"]
    if (
        scan_outcome == "success" and type(exit_code) is int and exit_code == 0
        and result.get("verdict") == "PASS" and result.get("status") == "COMPLETED"
        and isinstance(scan_uuid, str) and scan_uuid
        and type(asr) in (int, float) and math.isfinite(asr) and same_run
    ):
        return 0
    return 1 if type(exit_code) is int and exit_code == 1 else 2


def notify(result, webhook, run_url):
    if not webhook:
        print("Slack notification skipped: SLACK_WEBHOOK_URL is not configured.")
        return 0
    if not webhook.startswith("https://"):
        print("Slack notification failed: webhook must use HTTPS.")
        return 2
    lines = [
        f"Nightly Red Team scan: {result.get('verdict', 'ERROR')}",
        f"Status: {result.get('status', 'UNKNOWN')}",
        f"ASR: {result.get('asr_percent', 'unknown')}%",
    ]
    if result.get("scan_uuid"):
        lines.append(f"Scan: {result['scan_uuid']}")
    if result.get("error"):
        lines.append(f"Error: {result['error']}")
    message = "\n".join(lines + [f"Run: {run_url}"])
    request = Request(webhook, data=json.dumps({"text": message}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=20) as response:
            if not 200 <= response.status < 300:
                print("Slack notification failed: unexpected HTTP status.")
                return 2
    except (URLError, OSError, ValueError):
        # Do not print the exception: it can include the secret webhook URL.
        print("Slack notification failed; check the webhook configuration.")
        return 2
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["summary", "notify", "enforce"])
    parser.add_argument("--result", default="red_team_result.json")
    parser.add_argument("--scan-outcome", default="failure")
    args = parser.parse_args(argv)
    result = read_result(args.result)
    if args.command == "summary":
        body = summary(result)
        print(body)
        if os.getenv("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
                output.write(body)
        return 0
    if args.command == "enforce":
        return enforce(result, args.scan_outcome)
    run_url = f"{os.getenv('GITHUB_SERVER_URL', 'https://github.com')}/{os.getenv('GITHUB_REPOSITORY', '')}/actions/runs/{os.getenv('GITHUB_RUN_ID', '')}"
    return notify(result, os.getenv("SLACK_WEBHOOK_URL", ""), run_url)


if __name__ == "__main__":
    raise SystemExit(main())
