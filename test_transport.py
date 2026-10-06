"""Bounded recovery for auth expiry and transient reads, with no POST replay."""
from unittest.mock import patch

import pytest
import requests

import redteam_scan as rs


def response(status=200, body=None, headers=None):
    import json
    result = requests.Response()
    result.status_code = status
    result._content_consumed = True
    result._content = json.dumps(body or {}).encode()
    result.headers.update(headers or {})
    return result


@pytest.mark.parametrize('operation', ['categories', 'targets', 'status', 'report', 'create'])
def test_refresh_on_each_authenticated_path(operation):
    with patch.object(rs, 'fetch_oauth_token', side_effect=['old', 'new']) as token:
        headers = rs.AuthenticatedHeaders('id', 'secret', 'tsg')
        body = {'uuid': 'job', 'status': 'COMPLETED', 'asr': 0, 'data': []}
        captured = []
        def request(*args, **kwargs):
            captured.append(kwargs['headers']['Authorization'])
            return response(401) if len(captured) == 1 else response(body=body)
        with patch.object(rs.requests, 'get', side_effect=request), patch.object(rs.requests, 'post', side_effect=request):
            if operation == 'categories':
                rs.list_categories('https://data.test', headers)
            elif operation == 'targets':
                rs.list_targets('https://mgmt.test', headers)
            elif operation == 'status':
                rs.get_scan_status('https://data.test', headers, 'job')
            elif operation == 'report':
                rs.fetch_report('https://data.test', headers, 'job', 'STATIC')
            else:
                rs.start_scan('https://data.test', headers, 'target', 'DYNAMIC', None)
        assert token.call_count == 2
        assert captured == ['Bearer old', 'Bearer new']


def test_repeated_401_does_not_loop():
    with patch.object(rs, 'fetch_oauth_token', return_value='token') as token:
        headers = rs.AuthenticatedHeaders('id', 'secret', 'tsg')
        with patch.object(rs.requests, 'get', side_effect=lambda *a, **k: response(401)) as get:
            with pytest.raises(requests.HTTPError):
                rs.get_scan_status('https://data.test', headers, 'job')
    assert token.call_count == 2
    assert get.call_count == 2


@pytest.mark.parametrize('status', [429, 500, 502, 503, 504])
def test_transient_get_retries(status):
    with patch.object(rs.requests, 'get', side_effect=[response(status, headers={'Retry-After': '0'}), response(body={'status': 'COMPLETED'})]) as get:
        assert rs.get_scan_status('https://data.test', {}, 'job')['status'] == 'COMPLETED'
    assert get.call_count == 2


@pytest.mark.parametrize('failure', [requests.ReadTimeout, requests.ConnectionError])
def test_transport_failure_retries_safe_reads(failure):
    with patch.object(rs.requests, 'get', side_effect=[failure(), response(body={'status': 'COMPLETED'})]) as get, patch.object(rs.time, 'sleep'):
        assert rs.get_scan_status('https://data.test', {}, 'job')['status'] == 'COMPLETED'
    assert get.call_count == 2


@pytest.mark.parametrize('failure', [requests.ReadTimeout, requests.ConnectionError])
def test_create_is_not_replayed_after_transport_failure(failure):
    with patch.object(rs.requests, 'post', side_effect=failure()) as post:
        with pytest.raises(RuntimeError, match='outcome is unknown'):
            rs.start_scan('https://data.test', {}, 'target', 'DYNAMIC', None)
    assert post.call_count == 1


@pytest.mark.parametrize('status', [400, 403, 404, 422])
def test_permanent_errors_are_not_retried(status):
    with patch.object(rs.requests, 'get', return_value=response(status)) as get:
        with pytest.raises(requests.HTTPError):
            rs.get_scan_status('https://data.test', {}, 'job')
    assert get.call_count == 1


def test_server_errors_do_not_replay_create():
    with patch.object(rs.requests, 'post', return_value=response(503)) as post:
        with pytest.raises(requests.HTTPError):
            rs.start_scan('https://data.test', {}, 'target', 'DYNAMIC', None)
    assert post.call_count == 1


def test_read_retry_budget():
    with patch.object(rs.requests, 'get', side_effect=lambda *a, **k: response(503)) as get, patch.object(rs.time, 'sleep') as sleep:
        with pytest.raises(requests.HTTPError):
            rs.get_scan_status('https://data.test', {}, 'job')
    assert get.call_count == 3
    assert sleep.call_count == 2


def test_retry_after_cannot_exceed_poll_deadline():
    with patch.object(rs.requests, 'get', return_value=response(429, headers={'Retry-After': '60'})) as get, patch.object(rs.time, 'monotonic', return_value=100), patch.object(rs.time, 'sleep') as sleep:
        with pytest.raises(TimeoutError):
            rs.get_scan_status('https://data.test', {}, 'job', deadline=110)
    assert get.call_args.kwargs['timeout'] == 10
    sleep.assert_not_called()


def test_poll_sleep_respects_remaining_budget():
    with patch.object(rs.time, 'monotonic', side_effect=[0, 0, 59, 60]), patch.object(rs.time, 'sleep') as sleep, patch.object(rs, 'get_scan_status', return_value={'status': 'RUNNING'}):
        with pytest.raises(TimeoutError):
            rs.poll_until_terminal('https://data.test', {}, 'job', 30, 1)
    sleep.assert_called_once_with(1)


@pytest.mark.parametrize("statuses", [[401, 200], [403, 200], [503, 200], [429, 200]])
def test_http_poll_recovers(tmp_path, statuses):
    from test_policy_regressions import EVIDENCE, api, run_scan
    with api({"asr": 0, **EVIDENCE}, poll_status=list(statuses)) as calls, patch.object(rs.time, "sleep"):
        assert run_scan(tmp_path) == 0
    assert sum(call[:2] == ("GET", "/v1/scan/review-job") for call in calls) == 2
    assert sum(call[:2] == ("POST", "/v1/scan") for call in calls) == 1
    assert sum(call[:2] == ("POST", "/token") for call in calls) == (2 if statuses[0] in (401, 403) else 1)


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("status,headers,refreshes", [
    (401, {}, True),
    (403, {}, True),
    (403, {"x-opa-decision": "true"}, True),
    (403, {"x-opa-decision": "false"}, False),
    (403, {"X-OPA-Decision": " FALSE "}, False),
])
def test_refresh_on_401_and_non_policy_403(method, status, headers, refreshes):
    with patch.object(rs, "fetch_oauth_token", side_effect=["old", "new"]) as token:
        auth = rs.AuthenticatedHeaders("id", "secret", "tsg")
        replies = [response(status, {"message": "denied"}, headers), response(body={"uuid": "job"})]
        with patch.object(rs.requests, method.lower(), side_effect=replies) as call:
            if refreshes:
                assert rs.api_request(method, "https://data.test/v1/scan", auth, timeout=5).json() == {"uuid": "job"}
            else:
                with pytest.raises(requests.HTTPError):
                    rs.api_request(method, "https://data.test/v1/scan", auth, timeout=5)
    assert token.call_count == (2 if refreshes else 1)
    assert call.call_count == (2 if refreshes else 1)


def test_repeated_403_refreshes_once():
    with patch.object(rs, "fetch_oauth_token", return_value="token") as token:
        auth = rs.AuthenticatedHeaders("id", "secret", "tsg")
        with patch.object(rs.requests, "get", side_effect=lambda *a, **k: response(403)) as get:
            with pytest.raises(requests.HTTPError):
                rs.get_scan_status("https://data.test", auth, "job")
    assert token.call_count == 2
    assert get.call_count == 2
