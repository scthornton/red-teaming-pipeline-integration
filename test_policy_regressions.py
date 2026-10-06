"""Policy regression tests using a local HTTP API and dummy credentials."""
import contextlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

import pytest

import redteam_scan as rs


@contextlib.contextmanager
def api(report, state='COMPLETED', poll_status=200):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def reply(self, status, body):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            calls.append(('POST', self.path, body.decode()))
            self.reply(200, {'access_token': 'dummy-review-token'} if self.path == '/token' else {'uuid': 'review-job'})
        def do_GET(self):
            calls.append(('GET', self.path, None))
            if self.path == '/v1/categories':
                self.reply(200, {'data': [{'id': 'SECURITY', 'sub_categories': [{'id': 'PROMPT_INJECTION'}, {'id': 'JAILBREAK'}]}]})
            elif self.path == '/v1/scan/review-job':
                code = poll_status.pop(0) if isinstance(poll_status, list) else poll_status
                self.reply(code, {'status': state, 'completed': 1, 'total': 100})
            else:
                self.reply(200, report)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    env = {
        'PRISMA_AIRS_CLIENT_ID': 'dummy-review-client',
        'PRISMA_AIRS_CLIENT_SECRET': 'dummy-review-secret',
        'PRISMA_AIRS_TSG_ID': 'dummy-review-tsg',
        'PRISMA_AIRS_TOKEN_ENDPOINT': base + '/token',
        'PRISMA_AIRS_RED_TEAM_DATA_ENDPOINT': base,
        'PRISMA_AIRS_RED_TEAM_MGMT_ENDPOINT': base,
    }
    try:
        with patch.dict(os.environ, env, clear=True):
            yield calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run_scan(tmp_path, extra=()):
    return rs.run(['--target-uuid', 'review-target', '--poll-interval', '1', '--report-out', str(tmp_path / 'report.json'), '--result-out', str(tmp_path / 'result.json'), *extra])

@pytest.mark.parametrize('report,extra,expected', [
    ({'asr': 1.09}, [], 0),
    ({'asr': 14.17}, ['--scan-type', 'DYNAMIC'], 1),
    ({'asr': 5.0}, [], 0),
    ({'asr': 5.01}, [], 1),
    ({'asr': 0.1, 'security_report': {'id': 'SECURITY', 'sub_categories': [{'id': 'PROMPT_INJECTION', 'successful': 1}]}}, ['--fail-on-categories', 'PROMPT_INJECTION'], 1),
])
def test_http_lifecycle(tmp_path, report, extra, expected):
    with api(report) as calls:
        assert run_scan(tmp_path, extra) == expected
    assert json.loads((tmp_path / 'report.json').read_text()) == report
    create = next(json.loads(c[2]) for c in calls if c[:2] == ('POST', '/v1/scan'))
    assert create['target'] == {'uuid': 'review-target'}
    if '--scan-type' not in extra:
        assert create['job_metadata']['categories']['SECURITY'] == ['PROMPT_INJECTION', 'JAILBREAK']

@pytest.mark.parametrize('state', ['FAILED', 'ABORTED'])
def test_failed_scan_is_error(tmp_path, state):
    with api({'asr': 0}, state):
        assert run_scan(tmp_path) == 2
    assert json.loads((tmp_path / 'report.json').read_text())['status'] == state

@pytest.mark.parametrize('report', [{}, {'asr': None}, {'asr': 'bad'}, {'asr': 'NaN'}, {'asr': -1}, {'asr': False}])
def test_invalid_asr_must_not_pass(tmp_path, report):
    with api(report):
        assert run_scan(tmp_path) == 2

@pytest.mark.parametrize('threshold', ['NaN', 'inf', '101'])
def test_invalid_threshold_must_not_pass(tmp_path, threshold):
    with api({'asr': 99}):
        assert run_scan(tmp_path, ['--max-asr-percent', threshold]) == 2

def test_partial_scan_must_not_pass_by_default(tmp_path):
    with api({'asr': 0}, 'PARTIALLY_COMPLETE'):
        assert run_scan(tmp_path) != 0

def test_compliance_group_policy_matches():
    report = {'asr': 0.1, 'compliance_report': [{'id': 'OWASP', 'techniques': [{'id': 'LLM01', 'successful': 1}]}]}
    assert rs.evaluate_policy(report, 5, {'COMPLIANCE'})

def test_misspelled_guardrail_must_not_pass(tmp_path):
    report = {'asr': 0.1, 'security_report': {'id': 'SECURITY', 'sub_categories': [{'id': 'PROMPT_INJECTION', 'successful': 1}]}}
    with api(report):
        assert run_scan(tmp_path, ['--fail-on-categories', 'PROMPT_INJECTON']) == 2

def test_unscanned_guardrail_must_not_pass(tmp_path):
    report = {'asr': 0, 'security_report': {'id': 'SECURITY', 'sub_categories': [{'id': 'JAILBREAK', 'successful': 0}]}}
    with api(report):
        assert run_scan(tmp_path, ['--categories', 'JAILBREAK', '--fail-on-categories', 'PROMPT_INJECTION']) == 2

def test_partly_invalid_selection_must_not_be_dropped(tmp_path):
    with api({'asr': 0}):
        assert run_scan(tmp_path, ['--categories', 'JAILBREAK,PROMPT_INJECTON']) == 2


@pytest.mark.parametrize("value", ["0", "-1", "bad"])
@pytest.mark.parametrize("flag", ["--poll-interval", "--max-wait-minutes"])
def test_invalid_time_limits(value, flag):
    assert rs.run([flag, value]) == 2


def test_empty_environment_uses_defaults():
    with patch.dict(os.environ, {"MAX_ASR_PERCENT": "", "MAX_WAIT_MINUTES": ""}, clear=True):
        args = rs.parse_arguments([])
    assert args.max_asr_percent == 5
    assert args.max_wait_minutes == 60


def test_cli_overrides_invalid_environment_default():
    with patch.dict(os.environ, {"MAX_ASR_PERCENT": "bad"}, clear=True):
        assert rs.parse_arguments(["--max-asr-percent", "3"]).max_asr_percent == 3


@pytest.mark.parametrize("extra", [["--fail-on-categories", "JAILBREAK"], ["--categories", "SECURITY"]])
def test_dynamic_rejects_category_options_without_api_calls(tmp_path, extra):
    with api({"asr": 0}) as calls:
        assert run_scan(tmp_path, ["--scan-type", "DYNAMIC", *extra]) == 2
    assert not calls


@pytest.mark.parametrize("count", [None, "bad", -1, 0.5, False])
def test_invalid_success_counts_are_not_clean_results(count):
    report = {"asr": 0, "security_report": {"id": "SECURITY", "sub_categories": [{"id": "JAILBREAK", "successful": count}]}}
    with pytest.raises(ValueError):
        rs.evaluate_policy(report, 5, {"JAILBREAK"})


def test_missing_success_count_is_not_clean_result():
    report = {"asr": 0, "security_report": {"id": "SECURITY", "sub_categories": [{"id": "JAILBREAK"}]}}
    with pytest.raises(ValueError, match="No measured results"):
        rs.evaluate_policy(report, 5, {"JAILBREAK"})


@pytest.mark.parametrize('extra', [
    ['--expected-sha', 'a' * 40],
    ['--expected-sha', 'a' * 40, '--deployed-sha', 'b' * 40],
    ['--expected-sha', 'short', '--deployed-sha', 'short'],
])
def test_deployment_mismatch_stops_before_auth(tmp_path, extra):
    with api({'asr': 0}) as calls:
        assert run_scan(tmp_path, extra) == 2
    assert not calls


def test_matching_deployment_identity_is_recorded(tmp_path):
    with api({'asr': 0}):
        assert run_scan(tmp_path, ['--expected-sha', 'a' * 40, '--deployed-sha', 'a' * 40]) == 0
    result = json.loads((tmp_path / 'result.json').read_text())
    assert result['expected_sha'] == result['deployed_sha'] == 'a' * 40
