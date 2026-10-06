#!/usr/bin/env python3
"""Summarize scan results and notify without requiring a report to exist."""
import argparse
import json
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


def summary(result):
    return "\n".join([
        "### Prisma AIRS Red Teaming",
        "",
        f"- Verdict: `{text(result.get('verdict', 'ERROR'))}`",
        f"- Scan status: `{text(result.get('status', 'UNKNOWN'))}`",
        f"- ASR: `{text(result.get('asr_percent'))}%`",
        f"- Target: `{text(result.get('target_uuid'))}`",
        f"- Scan: `{text(result.get('scan_uuid'))}`",
        "",
    ])


def enforce(result, scan_outcome):
    if scan_outcome == "success" and result.get("exit_code") == 0 and result.get("verdict") == "PASS" and result.get("status") == "COMPLETED":
        return 0
    return 1 if result.get("exit_code") == 1 else 2


def notify(result, webhook, run_url):
    if not webhook:
        print("Slack notification skipped: SLACK_WEBHOOK_URL is not configured.")
        return 0
    if not webhook.startswith("https://"):
        print("Slack notification failed: webhook must use HTTPS.")
        return 2
    message = (
        f"Nightly Red Team scan: {result.get('verdict', 'ERROR')}\n"
        f"Status: {result.get('status', 'UNKNOWN')}\n"
        f"ASR: {result.get('asr_percent', 'unknown')}%\n"
        f"Run: {run_url}"
    )
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
