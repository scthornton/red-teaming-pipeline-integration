"""Result artifacts, failure propagation, and workflow input boundaries."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest
import yaml

import ci_report
import redteam_scan as rs
from test_policy_regressions import EVIDENCE, api, run_scan

REPO = Path(__file__).parent


@pytest.mark.parametrize('report,state,code,verdict', [
    ({'asr': 0, **EVIDENCE}, 'COMPLETED', 0, 'PASS'),
    ({'asr': 20, **EVIDENCE}, 'COMPLETED', 1, 'FAIL'),
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
    assert result['error'] == 'HTTP 403: simulated 403'
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


PASSING = {'exit_code': 0, 'verdict': 'PASS', 'status': 'COMPLETED', 'scan_uuid': 'review-job', 'asr_percent': 0.5}


@pytest.mark.parametrize('outcome,result,code', [
    ('success', PASSING, 0),
    ('success', {**PASSING, 'asr_percent': 0}, 0),
    ('failure', {'exit_code': 1, 'verdict': 'FAIL', 'status': 'COMPLETED'}, 1),
    ('failure', {'exit_code': 2}, 2),
    ('failure', PASSING, 2),
    ('success', {**PASSING, 'scan_uuid': None}, 2),
    ('success', {**PASSING, 'scan_uuid': ''}, 2),
    ('success', {**PASSING, 'asr_percent': None}, 2),
    ('success', {**PASSING, 'asr_percent': '0.5'}, 2),
    ('success', {**PASSING, 'asr_percent': True}, 2),
    ('success', {**PASSING, 'exit_code': False}, 2),
    ('success', {**PASSING, 'exit_code': 0.0}, 2),
    ('failure', {**PASSING, 'exit_code': True, 'verdict': 'FAIL'}, 2),
    ('success', {**PASSING, 'status': 'PARTIALLY_COMPLETE'}, 2),
    ('success', {}, 2),
    ('skipped', {}, 2),
    ('cancelled', {}, 2),
])
def test_enforcement_requires_both_step_and_result(monkeypatch, outcome, result, code):
    monkeypatch.delenv('GITHUB_RUN_ID', raising=False)
    assert ci_report.enforce(result, outcome) == code


@pytest.mark.parametrize('run_id,code', [('42', 0), ('41', 2), (None, 2)])
def test_enforcement_binds_result_to_current_run(monkeypatch, run_id, code):
    monkeypatch.setenv('GITHUB_RUN_ID', '42')
    assert ci_report.enforce({**PASSING, 'run_id': run_id}, 'success') == code


def test_summary_reports_policy_error_and_recovery_hint():
    body = ci_report.summary({
        'verdict': 'ERROR', 'status': 'RUNNING', 'scan_uuid': 'job-`1`', 'error': 'HTTP 400: <bad> `x`',
        'policy': {'max_asr_percent': 2.5, 'fail_on_categories': ['JAILBREAK', 'PROMPT_INJECTION']},
    })
    assert "- Policy: max ASR `2.5%`, protected categories `JAILBREAK, PROMPT_INJECTION`" in body
    assert "- Error: `HTTP 400: &lt;bad&gt; 'x'`" in body
    assert "re-run with `--scan-uuid job-'1'` to evaluate it without starting a new scan." in body
    assert body.count('`') % 2 == 0


@pytest.mark.parametrize('result', [
    {'verdict': 'PASS', 'scan_uuid': 'job'},
    {'verdict': 'FAIL', 'scan_uuid': 'job'},
    {'verdict': 'ERROR', 'scan_uuid': None},
])
def test_summary_hint_only_for_unresolved_scans(result):
    body = ci_report.summary(result)
    assert '--scan-uuid' not in body
    assert 'Error:' not in body
    assert 'protected categories `none`' in body or 'protected categories `unknown`' in body


def test_notification_includes_scan_and_error(capsys):
    response = MagicMock()
    response.__enter__.return_value.status = 200
    webhook = 'https://example.test/private-webhook-token'
    with patch.object(ci_report, 'urlopen', return_value=response) as post:
        assert ci_report.notify({'verdict': 'ERROR', 'scan_uuid': 'job-9', 'error': 'HTTP 400: bad'}, webhook, 'run') == 0
    text = json.loads(post.call_args.args[0].data)['text']
    assert 'Scan: job-9' in text
    assert 'Error: HTTP 400: bad' in text
    assert webhook not in capsys.readouterr().out


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
    # The workflow may call the scanner from a separate checkout directory.
    script = re.sub(r'python \S*ci_report\.py', lambda _: f'{sys.executable} {REPO / "ci_report.py"}', workflow[-1]['run'])
    completed = subprocess.run(['/bin/bash', '-e', '-c', script], cwd=tmp_path, env={'PATH': '/usr/bin:/bin', 'SCAN_OUTCOME': 'failure'}, capture_output=True, text=True)
    assert completed.returncode == code


def test_cli_commands_read_result_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'result.json'
    path.write_text(json.dumps({**PASSING, 'run_id': '7', 'policy': {'max_asr_percent': 5, 'fail_on_categories': []}}))
    step_summary = tmp_path / 'summary.md'
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(step_summary))
    monkeypatch.setenv('GITHUB_RUN_ID', '7')
    monkeypatch.delenv('SLACK_WEBHOOK_URL', raising=False)
    assert ci_report.main(['summary', '--result', str(path)]) == 0
    assert 'protected categories `none`' in step_summary.read_text()
    assert ci_report.main(['enforce', '--result', str(path), '--scan-outcome', 'success']) == 0
    assert ci_report.main(['enforce', '--result', str(tmp_path / 'missing.json'), '--scan-outcome', 'success']) == 2
    assert ci_report.main(['notify', '--result', str(path)]) == 0
    assert 'notification skipped' in capsys.readouterr().out
