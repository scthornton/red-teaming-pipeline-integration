"""Workflow wiring: pinned actions, scanner checkout, and dispatch arguments."""
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml

REPO = Path(__file__).parent
WORKFLOWS = sorted((REPO / '.github/workflows').glob('*.yml'))
EXAMPLES = sorted((REPO / 'examples').glob('*.yml'))
USES = re.compile(r'uses:\s*(actions/[\w-]+)@(\S+)')


def pins(paths):
    found = {}
    for path in paths:
        for action, ref in USES.findall(path.read_text()):
            found.setdefault(action, set()).add(ref)
    return found


def steps(path, job):
    return yaml.safe_load(path.read_text())['jobs'][job]['steps']


def test_actions_are_sha_pinned():
    for action, refs in pins(WORKFLOWS + EXAMPLES).items():
        assert all(re.fullmatch(r'[0-9a-f]{40}', ref) for ref in refs), action


def test_examples_match_workflow_pins():
    # Dependabot only updates .github/workflows/, so examples drift silently.
    current = pins(WORKFLOWS)
    for action, refs in pins(EXAMPLES).items():
        assert refs == current[action], f'{action} in examples/ differs from .github/workflows/'


@pytest.mark.parametrize('path,job', [
    (REPO / 'examples/example-pr-workflow.yml', 'red_teaming_scan'),
    (REPO / 'examples/example-nightly-workflow.yml', 'nightly_red_team'),
])
def test_examples_run_the_pinned_scanner(path, job):
    workflow = steps(path, job)
    checkout = workflow[0]
    assert checkout['uses'].startswith('actions/checkout@')
    assert checkout['with']['repository'] == 'scthornton/red-teaming-pipeline-integration'
    assert checkout['with']['path'] == '.airs-scanner'
    assert checkout['with']['persist-credentials'] is False
    assert re.fullmatch(r'v\d+\.\d+\.\d+', checkout['with']['ref'])
    for step in workflow[1:]:
        run = step.get('run', '')
        for script in ('redteam_scan.py', 'ci_report.py', 'requirements.txt'):
            if script in run:
                assert f'.airs-scanner/{script}' in run, f'{script} must come from the scanner checkout'


def dispatch(tmp_path, **env):
    script = next(step['run'] for step in steps(REPO / '.github/workflows/red_teaming_scan.yml', 'red_teaming_scan') if step.get('id') == 'scan')
    output = tmp_path / 'args.json'
    stub = tmp_path / 'python'
    stub.write_text(f'#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\nPath({str(output)!r}).write_text(json.dumps(sys.argv[1:]))\n')
    stub.chmod(0o700)
    base = {'PATH': str(tmp_path) + ':/usr/bin:/bin', 'TARGET_UUID': 't', 'SCAN_TYPE': 'STATIC', 'SCAN_CATEGORIES': '', 'MAX_ASR_PERCENT': '5', 'FAIL_ON_CATEGORIES': '', 'MAX_WAIT_MINUTES': '240'}
    result = subprocess.run(['/bin/bash', '-e', '-c', script], env={**base, **env}, capture_output=True, text=True)
    return result.returncode, json.loads(output.read_text()) if output.exists() else None


def test_dispatch_starts_a_new_scan_without_scan_uuid(tmp_path):
    code, args = dispatch(tmp_path, SCAN_CATEGORIES='PROMPT_INJECTION')
    assert code == 0
    assert '--scan-uuid' not in args
    assert args[args.index('--scan-type') + 1] == 'STATIC'
    assert args[args.index('--categories') + 1] == 'PROMPT_INJECTION'


def test_dispatch_attaches_without_scan_type_or_categories(tmp_path):
    # The attached job decides its type and scope; passing them would conflict.
    code, args = dispatch(tmp_path, SCAN_UUID='4c68d8c0-52d6-4b8f-9a3b-9c3fd91c414c', SCAN_CATEGORIES='JAILBREAK')
    assert code == 0
    assert args[args.index('--scan-uuid') + 1] == '4c68d8c0-52d6-4b8f-9a3b-9c3fd91c414c'
    assert '--scan-type' not in args and '--categories' not in args


@pytest.mark.parametrize('wait,ok', [('1', True), ('240', True), ('300', True), ('0', False), ('301', False), ('075', False), ('', False)])
def test_dispatch_wait_budget_fits_the_job(tmp_path, wait, ok):
    code, args = dispatch(tmp_path, MAX_WAIT_MINUTES=wait)
    assert (code == 0) is ok
    assert (args is not None) is ok
