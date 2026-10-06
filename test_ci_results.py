"""Result artifacts, failure propagation, and workflow input boundaries."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest
import yaml

import ci_report
import redteam_scan as rs
from test_policy_regressions import api, run_scan

REPO = Path(__file__).parent


@pytest.mark.parametrize('report,state,code,verdict', [
    ({'asr': 0}, 'COMPLETED', 0, 'PASS'),
    ({'asr': 20}, 'COMPLETED', 1, 'FAIL'),
    ({}, 'COMPLETED', 2, 'ERROR'),
    ({'asr': 0}, 'PARTIALLY_COMPLETE', 2, 'ERROR'),
    ({'asr': 0}, 'FAILED', 2, 'ERROR'),
])
def test_result_records_identity_status_and_verdict(tmp_path, report, state, code, verdict):
    with api(report, state):
        assert run_scan(tmp_path) == code
    result = json.loads((tmp_path / 'result.json').read_text())
    assert result['scan_uuid'] == 'review-job'
    assert result['target_uuid'] == 'review-target'
    assert result['status'] == state
    assert result['exit_code'] == code
    assert result['verdict'] == verdict
    assert result['policy']['max_asr_percent'] == 5
    assert result['finished_at']


def test_result_survives_poll_error_and_removes_stale_report(tmp_path):
    report = tmp_path / 'report.json'
    report.write_text('{"asr": 0}')
    with api({}, poll_status=403):
        assert run_scan(tmp_path) == 2
    result = json.loads((tmp_path / 'result.json').read_text())
    assert result['scan_uuid'] == 'review-job'
    assert result['verdict'] == 'ERROR'
    assert result['error'] == 'HTTP 403'
    assert not report.exists()


def test_auth_configuration_failure_has_result(tmp_path):
    with patch.dict(os.environ, {}, clear=True):
        assert run_scan(tmp_path) == 2
    result = json.loads((tmp_path / 'result.json').read_text())
    assert result['status'] == 'NOT_STARTED'
    assert result['verdict'] == 'ERROR'


def test_checkpoint_exists_before_polling(tmp_path):
    def polling(*args, **kwargs):
        result = json.loads((tmp_path / 'result.json').read_text())
        assert result['scan_uuid'] == 'review-job'
        assert result['verdict'] == 'PENDING'
        raise TimeoutError('simulated deadline')
    with api({}), patch.object(rs, 'poll_until_terminal', side_effect=polling):
        assert run_scan(tmp_path) == 2


def test_output_paths_cannot_collide(tmp_path):
    target = tmp_path / 'report.json'
    target.write_text('untouched')
    with api({}):
        assert run_scan(tmp_path, ['--result-out', str(target)]) == 2
    assert target.read_text() == 'untouched'


@pytest.mark.parametrize('outcome,result,code', [
    ('success', {'exit_code': 0, 'verdict': 'PASS', 'status': 'COMPLETED'}, 0),
    ('failure', {'exit_code': 1, 'verdict': 'FAIL', 'status': 'COMPLETED'}, 1),
    ('failure', {'exit_code': 2}, 2),
    ('failure', {'exit_code': 0, 'verdict': 'PASS', 'status': 'COMPLETED'}, 2),
    ('success', {}, 2),
    ('skipped', {}, 2),
    ('cancelled', {}, 2),
])
def test_enforcement_requires_both_step_and_result(outcome, result, code):
    assert ci_report.enforce(result, outcome) == code


def test_missing_report_can_notify(tmp_path):
    result = ci_report.read_result(tmp_path / 'missing.json')
    response = MagicMock()
    response.__enter__.return_value.status = 200
    with patch.object(ci_report, 'urlopen', return_value=response) as post:
        assert ci_report.notify(result, 'https://example.test/dummy-webhook', 'https://example.test/run') == 0
    body = json.loads(post.call_args.args[0].data)
    assert 'NO_RESULT' in body['text']
    assert 'ERROR' in body['text']


def test_notification_encodes_json_and_redacts_webhook(capsys):
    webhook = 'https://example.test/private-webhook-token'
    with patch.object(ci_report, 'urlopen', side_effect=URLError(webhook)):
        assert ci_report.notify({'status': 'quote"\nline'}, webhook, 'run') == 2
    assert webhook not in capsys.readouterr().out


def steps(path, job):
    return yaml.safe_load((REPO / path).read_text())['jobs'][job]['steps']


def test_dispatch_values_are_data_not_shell(tmp_path):
    script = next(step['run'] for step in steps('.github/workflows/red_teaming_scan.yml', 'red_teaming_scan') if step.get('id') == 'scan')
    assert '${{' not in script
    marker = tmp_path / 'should-not-exist'
    output = tmp_path / 'args.json'
    stub = tmp_path / 'python'
    stub.write_text(f'#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\nPath({str(output)!r}).write_text(json.dumps(sys.argv[1:]))\n')
    stub.chmod(0o700)
    payload = f'$(touch {marker})'
    env = {'PATH': str(tmp_path) + ':/usr/bin:/bin', 'TARGET_UUID': payload, 'SCAN_TYPE': 'STATIC', 'SCAN_CATEGORIES': payload, 'MAX_ASR_PERCENT': '5', 'FAIL_ON_CATEGORIES': payload, 'MAX_WAIT_MINUTES': '60'}
    result = subprocess.run(['/bin/bash', '-e', '-c', script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert json.loads(output.read_text()).count(payload) == 3


def test_nightly_cannot_finish_without_enforcing_result():
    workflow = steps('examples/example-nightly-workflow.yml', 'nightly_red_team')
    scan = next(step for step in workflow if step.get('id') == 'scan')
    assert scan['continue-on-error'] is True
    assert 'set +e' not in scan['run']
    assert workflow[-1]['if'] == 'always()'
    assert 'ci_report.py enforce' in workflow[-1]['run']


@pytest.mark.parametrize('code', [1, 2])
def test_nightly_final_shell_step_propagates_exit(tmp_path, code):
    result = tmp_path / 'red_team_result.json'
    result.write_text(json.dumps({'exit_code': code}))
    workflow = steps('examples/example-nightly-workflow.yml', 'nightly_red_team')
    script = workflow[-1]['run'].replace('python ci_report.py', f'{sys.executable} {REPO / "ci_report.py"}')
    completed = subprocess.run(['/bin/bash', '-e', '-c', script], cwd=tmp_path, env={'PATH': '/usr/bin:/bin', 'SCAN_OUTCOME': 'failure'}, capture_output=True, text=True)
    assert completed.returncode == code
