"""Behavior pinned to the live API contract verified in October 2026."""
import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

import redteam_scan as rs
from test_policy_regressions import EVIDENCE, api, run_scan
from test_transport import response

FIXTURES = Path(__file__).parent / 'fixtures'
LIVE_CATEGORIES = json.loads((FIXTURES / 'categories_live_2026-10.json').read_text())
STATIC_LIVE = json.loads((FIXTURES / 'static_report_live_2026-07.json').read_text())
DYNAMIC_LIVE = json.loads((FIXTURES / 'dynamic_report_live_2026-07.json').read_text())
OPTIONAL = {'MULTI_TURN', 'TOOL_LEAK', 'INDIRECT_PROMPT_INJECTION'}
# The exact body POST /v1/scan returned for the old select-everything default.
LIVE_400 = {'code': 'invalid_request', 'message': 'Target does not support multi-turn: Multi turn configuration JSON not provided. Please revalidate the target.'}
# Job records embed the target config; these markers must never reach artifacts.
JOB = {
    'uuid': 'review-job', 'name': 'ci-redteam-static', 'job_type': 'STATIC', 'target_id': 'review-target',
    'extra_info': None, 'progress': {'kind': 'standard'}, 'created_at': '2026-10-06T00:00:00Z',
    'target': {'uuid': 'review-target', 'additional_context': {'system_prompt': 'PLANTED-TARGET-PROMPT'}},
    'job_metadata': {'system_prompt': 'PLANTED-METADATA-PROMPT', 'categories': {'SECURITY': ['PROMPT_INJECTION', 'JAILBREAK']}},
}
DYNAMIC_JOB = {**JOB, 'job_type': 'DYNAMIC', 'job_metadata': {'system_prompt': 'PLANTED-METADATA-PROMPT', 'stream_breadth': 6, 'stream_depth': 10}}


def selection(selected=None):
    with patch.object(rs, 'list_categories', return_value=LIVE_CATEGORIES):
        return rs.build_static_categories('https://data.test', {}, selected)


def flat(categories_map):
    return {sub for subs in categories_map.values() for sub in subs}


def attach(tmp_path, extra=()):
    return rs.run(['--scan-uuid', 'review-job', '--poll-interval', '1', '--report-out', str(tmp_path / 'report.json'), '--result-out', str(tmp_path / 'result.json'), *extra])


def result_of(tmp_path):
    return json.loads((tmp_path / 'result.json').read_text())


def artifacts(tmp_path):
    return ''.join(path.read_text() for path in (tmp_path / 'report.json', tmp_path / 'result.json') if path.exists())


# --- 1. default STATIC scope mirrors the SCM UI ------------------------------


def test_default_selection_matches_scm_preselection():
    chosen = selection()
    assert set(chosen) == {'SECURITY', 'SAFETY', 'BRAND', 'COMPLIANCE'}
    assert not flat(chosen) & OPTIONAL
    assert len(flat(chosen)) == 25
    assert chosen['SECURITY'] == ['ADVERSARIAL_SUFFIX', 'EVASION', 'JAILBREAK', 'PROMPT_INJECTION', 'REMOTE_CODE_EXECUTION', 'SYSTEM_PROMPT_LEAK', 'MALWARE_GENERATION']


def test_group_selection_uses_preselected_subcategories():
    chosen = selection({'SECURITY'})
    assert list(chosen) == ['SECURITY']
    assert not flat(chosen) & OPTIONAL


def test_explicit_optional_subcategory_is_allowed(capsys):
    assert selection({'TOOL_LEAK'}) == {'SECURITY': ['TOOL_LEAK']}
    assert 'TOOL_LEAK (requires Tool Calling Support)' in capsys.readouterr().out
    assert 'TOOL_LEAK' in selection({'SECURITY', 'TOOL_LEAK'})['SECURITY']


def test_explicit_inactive_subcategory_is_rejected():
    with pytest.raises(ValueError, match=r'^MULTI_TURN is not active in the attack catalog \(requires Session Management Support\)$'):
        selection({'SECURITY', 'MULTI_TURN'})


def test_unknown_names_are_still_rejected():
    with pytest.raises(ValueError, match='Unknown scan categories: NOPE'):
        selection({'NOPE'})


def test_group_without_eligible_subcategories_is_omitted():
    vocabulary = [
        {'id': 'SECURITY', 'sub_categories': [{'id': 'TOOL_LEAK', 'preselect': False, 'active': True}]},
        {'id': 'SAFETY', 'sub_categories': [{'id': 'BIAS'}]},
    ]
    with patch.object(rs, 'list_categories', return_value=vocabulary):
        assert rs.build_static_categories('https://data.test', {}) == {'SAFETY': ['BIAS']}
        assert rs.build_static_categories('https://data.test', {}, {'SECURITY'}) == {}


def test_live_default_scan_body_excludes_capability_gated_attacks(tmp_path):
    with api({'asr': 0, **EVIDENCE}, categories=LIVE_CATEGORIES) as calls:
        assert run_scan(tmp_path) == 0
    create = next(json.loads(c[2]) for c in calls if c[:2] == ('POST', '/v1/scan'))
    assert not flat(create['job_metadata']['categories']) & OPTIONAL
    assert result_of(tmp_path)['scan_categories'] == create['job_metadata']['categories']


@pytest.mark.parametrize('vocabulary,extra,message', [
    (LIVE_CATEGORIES, ['--fail-on-categories', 'MULTI_TURN'], 'outside the scan scope: MULTI_TURN'),
    (LIVE_CATEGORIES, ['--categories', 'MULTI_TURN'], 'MULTI_TURN is not active'),
    ([{'id': 'SECURITY', 'sub_categories': [{'id': 'TOOL_LEAK', 'preselect': False}]}], ['--categories', 'SECURITY'], 'no active, preselected subcategories'),
])
def test_scope_errors_stop_before_scan_creation(tmp_path, capsys, vocabulary, extra, message):
    with api({}, categories=vocabulary) as calls:
        assert run_scan(tmp_path, extra) == 2
    assert not any(c[:2] == ('POST', '/v1/scan') for c in calls)
    assert message in capsys.readouterr().out
    assert message in result_of(tmp_path)['error']


def test_list_categories_marks_non_default_subcategories(capsys):
    with api({}, categories=LIVE_CATEGORIES):
        assert rs.run(['--list-categories']) == 0
    out = capsys.readouterr().out
    lines = {line.split()[1]: line for line in out.splitlines() if line.startswith('      - ')}
    assert lines['MULTI_TURN'].endswith('[inactive (requires Session Management Support)]')
    assert lines['TOOL_LEAK'].endswith('[not preselected (requires Tool Calling Support)]')
    assert lines['JAILBREAK'].endswith('(Jailbreak)')


# --- 2. API error reasons ------------------------------------------------------


def test_live_400_reason_is_surfaced(tmp_path, capsys):
    with api({}, create=(400, LIVE_400)):
        assert run_scan(tmp_path) == 2
    out = capsys.readouterr().out
    result = result_of(tmp_path)
    assert f"HTTP ERROR: status 400: {LIVE_400['message']}" in out
    assert result['error'] == f"HTTP 400: {LIVE_400['message']}"
    assert result['scan_uuid'] is None
    for secret in ('dummy-review-token', 'dummy-review-secret'):
        assert secret not in out
        assert secret not in json.dumps(result)


def raw(status, content):
    result = requests.Response()
    result.status_code = status
    result._content = content.encode()
    return result


@pytest.mark.parametrize('reply,reason', [
    (response(400, {'message': 'bad  \n input'}), 'bad input'),
    (response(422, {'detail': [{'loc': ['body'], 'msg': 'missing'}]}), '[{"loc": ["body"], "msg": "missing"}]'),
    (response(401, {'error': 'invalid_client'}), 'invalid_client'),
    (response(400, {'message': '', 'detail': 'second key'}), 'second key'),
    (raw(502, '<html> Bad   Gateway </html>'), '<html> Bad Gateway </html>'),
    (raw(500, '"plain json string"'), 'plain json string'),
    (response(400, {'message': 'echo Authorization: Bearer abc.def'}), 'echo Authorization: Bearer [REDACTED]'),
    (raw(400, ''), ''),
    (None, ''),
])
def test_http_error_reason(reply, reason):
    assert rs.http_error_reason(reply) == reason


def test_http_error_reason_is_truncated():
    assert len(rs.http_error_reason(response(400, {'message': 'x' * 1000}))) == 300


# --- 3. no PASS without executed attacks ----------------------------------------


def zeroed(value):
    if isinstance(value, dict):
        return {k: 0 if k in ('successful', 'failed', 'total', 'total_attacks') else zeroed(v) for k, v in value.items()}
    if isinstance(value, list):
        return [zeroed(v) for v in value]
    return value


def test_live_static_report_is_evaluated():
    assert rs.evaluate_policy(STATIC_LIVE, 5, set()) is True  # ASR 8.24
    assert rs.evaluate_policy(STATIC_LIVE, 10, {'ADVERSARIAL_SUFFIX', 'BRAND'}) is True  # BRAND had successes
    assert rs.evaluate_policy(STATIC_LIVE, 10, {'ADVERSARIAL_SUFFIX', 'POLITICAL_ENDORSEMENTS'}, job_type='STATIC') is False
    assert rs.evaluate_policy(STATIC_LIVE, 10, {'TOOL_LEAK'}) is True


def test_live_dynamic_report_is_evaluated():
    assert rs.evaluate_policy(DYNAMIC_LIVE, 25, set()) is False  # ASR 21.5
    assert rs.evaluate_policy(DYNAMIC_LIVE, 5, set(), job_type='DYNAMIC') is True


@pytest.mark.parametrize('report,job_type', [
    ({**zeroed(STATIC_LIVE), 'asr': 0}, None),
    ({**zeroed(STATIC_LIVE), 'asr': 0}, 'STATIC'),
    ({'asr': 0}, 'STATIC'),
    ({'asr': 0, 'by_category': [{'category': 'DLP', 'successes': 0}]}, None),
    ({'asr': 0, 'severity_report': {'total_attacks': 0}}, None),
    ({'asr': 0, 'security_report': {'id': 'SECURITY', 'sub_categories': [{'id': 'JAILBREAK', 'successful': 0, 'total': 0}]}}, None),
    ({**DYNAMIC_LIVE, 'total_goals': 0}, None),
    ({**DYNAMIC_LIVE, 'total_streams': 0}, 'DYNAMIC'),
    ({**DYNAMIC_LIVE, 'total_streams': True}, None),
    ({**DYNAMIC_LIVE, 'total_goals': '10'}, None),
    ({'asr': 0, 'total_streams': 60}, 'DYNAMIC'),
    (DYNAMIC_LIVE, 'STATIC'),
    (STATIC_LIVE, 'DYNAMIC'),
])
def test_zero_attempt_reports_cannot_pass(report, job_type):
    with pytest.raises(ValueError, match='no executed'):
        rs.evaluate_policy(report, 100, set(), job_type=job_type)


@pytest.mark.parametrize('report,extra', [
    ({**zeroed(STATIC_LIVE), 'asr': 0}, []),
    ({'asr': 0, 'total_goals': 0, 'total_streams': 0}, ['--scan-type', 'DYNAMIC']),
])
def test_zero_attempt_scan_is_error_not_pass(tmp_path, report, extra):
    with api(report):
        assert run_scan(tmp_path, extra) == 2
    result = result_of(tmp_path)
    assert result['verdict'] == 'ERROR'
    assert 'no executed' in result['error']


def test_invalid_attack_totals_are_errors():
    with pytest.raises(ValueError, match='total_attacks'):
        rs.evaluate_policy({'asr': 0, 'severity_report': {'total_attacks': 'many'}}, 5, set())


@pytest.mark.parametrize('entry,measured', [
    ({'successful': 0, 'failed': 0, 'total': 12}, True),
    ({'successful': 0, 'failed': 3}, True),
    ({'successful': 2}, True),
    ({'successful': 0}, False),
    ({'successful': 0, 'failed': 0, 'total': 0}, False),
    ({'active': False, 'successful': 0, 'total': 120}, False),
    ({'active': False, 'successful': 0, 'failed': 36, 'total': 36}, True),
    ({'active': False, 'successful': 4, 'total': 0}, True),
])
def test_measured_requires_an_attempt(entry, measured):
    report = {'security_report': {'id': 'SECURITY', 'sub_categories': [{'id': 'JAILBREAK', **entry}]}}
    assert ('JAILBREAK' in rs.category_evidence(report)[1]) is measured


def test_inactive_subcategory_with_zero_results_cannot_be_protected():
    report = {'asr': 0, **EVIDENCE, 'security_report': {'id': 'SECURITY', 'successful': 0, 'failed': 10, 'sub_categories': [
        {'id': 'MULTI_TURN', 'active': False, 'successful': 0, 'total': 120}]}}
    with pytest.raises(ValueError, match='No measured results for protected categories: MULTI_TURN'):
        rs.evaluate_policy(report, 5, {'MULTI_TURN'})
    assert rs.evaluate_policy(report, 5, {'SECURITY'}) is False  # the group's own counts are evidence


def test_inactive_compliance_technique_with_executed_failures_is_measured():
    # Live compliance reports mark OWASP 2025 techniques inactive while reporting real attempts.
    report = {'asr': 0, **EVIDENCE, 'compliance_report': [{'id': 'OWASP', 'techniques': [
        {'id': 'LLM02:2025', 'active': False, 'successful': 0, 'failed': 36, 'total': 36}]}]}
    assert rs.evaluate_policy(report, 5, {'COMPLIANCE', 'OWASP'}) is False


def test_legacy_breakdown_still_needs_executed_attacks():
    legacy = {'asr': 0, 'by_category': {'DLP': {'successes': 2}}}
    with pytest.raises(ValueError, match='no executed attacks'):
        rs.evaluate_policy(legacy, 5, {'DLP'})
    assert rs.evaluate_policy({**legacy, **EVIDENCE}, 5, {'DLP'}) is True


# --- 4. sanitized failure artifacts --------------------------------------------


def test_failed_job_artifacts_omit_target_config(tmp_path):
    with api({}, state='FAILED', job=JOB):
        assert run_scan(tmp_path) == 2
    saved = json.loads((tmp_path / 'report.json').read_text())
    state = {'status': 'FAILED', 'completed': 1, 'total': 100, **JOB}
    assert saved == {key: value for key, value in state.items() if key in rs.JOB_SUMMARY_KEYS}
    assert 'target' not in saved and 'job_metadata' not in saved
    assert 'PLANTED' not in artifacts(tmp_path)


@pytest.mark.parametrize('state,code', [('FAILED', 2), ('ABORTED', 2), ('COMPLETED', 0)])
def test_attached_job_artifacts_omit_target_config(tmp_path, state, code):
    with api({'asr': 0, **EVIDENCE}, state=state, job=JOB):
        assert attach(tmp_path) == code
    assert 'PLANTED' not in artifacts(tmp_path)


def test_job_summary_ignores_non_objects():
    assert rs.job_summary(['not', 'a', 'job']) == {}


# --- 5. explicit DYNAMIC scan size ---------------------------------------------


@pytest.mark.parametrize('extra,metadata', [
    ([], {'stream_breadth': 6, 'stream_depth': 10}),
    (['--stream-breadth', '2'], {'stream_breadth': 2, 'stream_depth': 10}),
    (['--stream-breadth', '3', '--stream-depth', '4'], {'stream_breadth': 3, 'stream_depth': 4}),
])
def test_dynamic_create_body_carries_scan_size(tmp_path, extra, metadata):
    with api({'asr': 0, 'total_goals': 10, 'total_streams': 60}) as calls:
        assert run_scan(tmp_path, ['--scan-type', 'DYNAMIC', *extra]) == 0
    create = next(json.loads(c[2]) for c in calls if c[:2] == ('POST', '/v1/scan'))
    assert create['job_metadata'] == metadata


@pytest.mark.parametrize('extra', [['--stream-breadth', '2'], ['--stream-depth', '2'], ['--scan-type', 'STATIC', '--stream-depth', '2']])
def test_scan_size_requires_dynamic(tmp_path, extra):
    with api({}) as calls:
        assert run_scan(tmp_path, extra) == 2
    assert not calls
    assert 'require DYNAMIC' in result_of(tmp_path)['error']


@pytest.mark.parametrize('extra', [['--stream-breadth', '0'], ['--stream-depth', '-1'], ['--stream-depth', 'x']])
def test_scan_size_must_be_positive(extra):
    assert rs.run(['--scan-type', 'DYNAMIC', *extra]) == 2


# --- 6. attach to an existing scan ---------------------------------------------


def test_attach_static_scan(tmp_path):
    report = {'asr': 0, **EVIDENCE, 'security_report': {'id': 'SECURITY', 'sub_categories': [{'id': 'PROMPT_INJECTION', 'successful': 0, 'failed': 5, 'total': 5}]}}
    with api(report, job=JOB) as calls:
        assert attach(tmp_path, ['--fail-on-categories', 'PROMPT_INJECTION']) == 0
    assert not any(c[0] == 'POST' and c[1] != '/token' for c in calls)
    assert not any(c[1] == '/v1/categories' for c in calls)
    assert ('GET', '/v1/report/static/review-job/report', None) in calls
    result = result_of(tmp_path)
    assert result['attached'] is True
    assert result['scan_uuid'] == 'review-job'
    assert result['target_uuid'] == 'review-target'
    assert result['job_type'] == 'STATIC'
    assert result['scan_categories'] == JOB['job_metadata']['categories']
    assert (result['verdict'], result['status']) == ('PASS', 'COMPLETED')


def test_attach_dynamic_scan_with_matching_options(tmp_path):
    with api({'asr': 9.0, 'total_goals': 10, 'total_streams': 60}, job={**DYNAMIC_JOB, 'target_id': None}) as calls:
        assert attach(tmp_path, ['--scan-type', 'DYNAMIC', '--target-uuid', 'REVIEW-TARGET']) == 1
    assert ('GET', '/v1/report/dynamic/review-job/report', None) in calls
    result = result_of(tmp_path)
    assert (result['job_type'], result['target_uuid'], result['verdict']) == ('DYNAMIC', 'review-target', 'FAIL')
    assert 'scan_categories' not in result


def test_attach_waits_for_a_running_scan(tmp_path):
    states = iter(['RUNNING', 'RUNNING', 'COMPLETED'])
    real = rs.get_scan_status
    def status(*args, **kwargs):
        return {**real(*args, **kwargs), 'status': next(states)}
    with api({'asr': 0, **EVIDENCE}, job=JOB), patch.object(rs, 'get_scan_status', side_effect=status), patch.object(rs.time, 'sleep'):
        assert attach(tmp_path) == 0
    assert result_of(tmp_path)['status'] == 'COMPLETED'


def test_new_scans_record_static_default_and_not_attached(tmp_path):
    with api({'asr': 0, **EVIDENCE}):
        assert run_scan(tmp_path) == 0
    result = result_of(tmp_path)
    assert (result['job_type'], result['attached']) == ('STATIC', False)


@pytest.mark.parametrize('extra,flag', [
    (['--categories', 'SECURITY'], '--categories'),
    (['--stream-breadth', '3'], '--stream-breadth'),
    (['--stream-depth', '3'], '--stream-depth'),
    (['--scan-name', 'my-scan'], '--scan-name'),
])
def test_attach_rejects_scope_options_before_api_calls(tmp_path, extra, flag):
    with api({}, job=JOB) as calls:
        assert attach(tmp_path, extra) == 2
    assert not calls
    result = result_of(tmp_path)
    assert flag in result['error']
    assert (result['attached'], result['job_type']) == (True, None)


@pytest.mark.parametrize('job,extra,message', [
    (JOB, ['--scan-type', 'DYNAMIC'], '--scan-type DYNAMIC does not match the existing STATIC scan'),
    (JOB, ['--target-uuid', 'other-target'], "--target-uuid does not match the scan's target (review-target)"),
    ({**JOB, 'target_id': None, 'target': None}, ['--target-uuid', 'review-target'], "target (unknown)"),
    (DYNAMIC_JOB, ['--fail-on-categories', 'JAILBREAK'], 'category guardrails require STATIC scans'),
    ({**JOB, 'job_type': 'CUSTOM'}, [], 'CUSTOM prompt sets are not supported'),
    (JOB, ['--fail-on-categories', 'TOOL_LEAK'], 'outside the scan scope: TOOL_LEAK'),
    ({**JOB, 'job_metadata': {}}, [], 'Scan categories must map'),
    ({**JOB, 'job_metadata': {'categories': {'SECURITY': 'JAILBREAK'}}}, [], 'Scan categories must map'),
    ({**JOB, 'job_type': None}, [], 'no recognized job type'),
])
def test_attach_rejects_mismatched_scan_before_polling(tmp_path, job, extra, message):
    with api({}, job=job) as calls:
        assert attach(tmp_path, extra) == 2
    assert [c[:2] for c in calls if c[1] != '/token'] == [('GET', '/v1/scan/review-job')]
    result = result_of(tmp_path)
    assert message in result['error']
    assert (result['scan_uuid'], result['attached'], result['verdict']) == ('review-job', True, 'ERROR')


def test_attach_rejects_non_object_scan_record(tmp_path):
    with api({}), patch.object(rs, 'get_scan_status', return_value=['job']):
        assert attach(tmp_path) == 2
    assert 'Scan record must be a JSON object' in result_of(tmp_path)['error']


def test_attach_missing_scan_reports_http_reason(tmp_path):
    with api({}, poll_status=404):
        assert attach(tmp_path) == 2
    result = result_of(tmp_path)
    assert result['error'] == 'HTTP 404: simulated 404'
    assert result['scan_uuid'] == 'review-job'


@pytest.mark.parametrize('value', ['../v1/target', 'job?x=1', 'a/b', '', '-job'])
def test_scan_uuid_must_be_path_safe(value):
    assert rs.run(['--scan-uuid', value]) == 2


# --- 8. scan name length --------------------------------------------------------


@pytest.mark.parametrize('name,valid', [('ab', False), ('abc', True), ('x' * 255, True), ('x' * 256, False)])
def test_scan_name_length(name, valid):
    if valid:
        assert rs.parse_arguments(['--scan-name', name]).scan_name == name
    else:
        with pytest.raises(SystemExit):
            rs.parse_arguments(['--scan-name', name])


# --- unexpected errors are recorded without request details ----------------------


def test_unexpected_error_is_recorded(tmp_path):
    with api({}), patch.object(rs, 'start_scan', side_effect=RuntimeError('Scan submission outcome is unknown.')):
        assert run_scan(tmp_path) == 2
    assert result_of(tmp_path)['error'] == 'RuntimeError: Scan submission outcome is unknown.'


def test_create_response_without_id_names_keys_only():
    reply = response(body={'target': {'additional_context': {'system_prompt': 'PLANTED'}}})
    with patch.object(rs.requests, 'post', return_value=reply):
        with pytest.raises(RuntimeError) as error:
            rs.start_scan('https://data.test', {}, 'target', 'DYNAMIC', None)
    assert 'PLANTED' not in str(error.value)
    assert "keys: ['target']" in str(error.value)


@pytest.mark.parametrize('value', [True, 1.5, -1, 'many'])
def test_attack_counters_reject_malformed_values(value):
    with pytest.raises(ValueError, match='Invalid failed count'):
        rs.attack_count({'failed': value}, 'failed')


def test_custom_metadata_is_not_built():
    assert rs.build_job_metadata('CUSTOM') == {}


@pytest.mark.parametrize('extra,message', [
    (['--scan-type', 'CUSTOM', '--target-uuid', 'review-target'], 'CUSTOM prompt sets are not supported'),
    ([], '--target-uuid is required'),
])
def test_new_scan_configuration_errors_are_recorded(tmp_path, extra, message):
    with api({}) as calls:
        assert rs.run(['--result-out', str(tmp_path / 'result.json'), '--report-out', str(tmp_path / 'report.json'), *extra]) == 2
    assert not calls
    assert message in result_of(tmp_path)['error']
