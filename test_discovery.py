"""Target pagination and policy checks against the committed report fixtures."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import redteam_scan as rs
from test_transport import response


def targets(start, end):
    return [{'uuid': f'target-{n}'} for n in range(start, end)]


def test_targets_follow_total_and_offsets():
    pages = [
        {'data': targets(0, 100), 'pagination': {'total_items': 101}},
        {'data': targets(100, 101), 'pagination': {'total_items': 101}},
    ]
    with patch.object(rs.requests, 'get', side_effect=[response(body=page) for page in pages]) as get:
        assert rs.list_targets('https://mgmt.test', {}) == targets(0, 101)
    assert [call.kwargs['params'] for call in get.call_args_list] == [
        {'limit': 100, 'skip': 0}, {'limit': 100, 'skip': 100},
    ]


def test_short_page_with_total_does_not_truncate():
    pages = [
        {'data': targets(0, 1), 'pagination': {'total_items': 2}},
        {'data': targets(1, 2), 'pagination': {'total_items': 2}},
    ]
    with patch.object(rs.requests, 'get', side_effect=[response(body=page) for page in pages]):
        assert rs.list_targets('https://mgmt.test', {}) == targets(0, 2)


def test_without_total_follows_full_pages_until_short_page():
    pages = [{'data': targets(0, 100)}, {'data': targets(100, 102)}]
    with patch.object(rs.requests, 'get', side_effect=[response(body=page) for page in pages]):
        assert rs.list_targets('https://mgmt.test', {}) == targets(0, 102)


def test_repeated_page_fails_instead_of_looping():
    with patch.object(rs.requests, 'get', side_effect=lambda *a, **k: response(body={'data': targets(0, 100)})) as get:
        with pytest.raises(ValueError, match='repeated a target'):
            rs.list_targets('https://mgmt.test', {})
    assert get.call_count == 2


def test_empty_page_with_remaining_total_is_error():
    with patch.object(rs.requests, 'get', return_value=response(body={'data': [], 'pagination': {'total_items': 1}})):
        with pytest.raises(ValueError, match='before all targets'):
            rs.list_targets('https://mgmt.test', {})


def test_legacy_bare_list():
    with patch.object(rs.requests, 'get', return_value=response(body=targets(0, 2))) as get:
        assert rs.list_targets('https://mgmt.test', {}) == targets(0, 2)
    assert get.call_count == 1


def test_empty_tenant():
    with patch.object(rs.requests, 'get', return_value=response(body={'data': [], 'pagination': {'total_items': 0}})):
        assert rs.list_targets('https://mgmt.test', {}) == []


@pytest.mark.parametrize('filename,asr,violation', [
    ('static_report_example.json', 1.09, False),
    ('dynamic_report_example.json', 14.17, True),
])
def test_committed_report_fixtures(filename, asr, violation):
    report = json.loads((Path(__file__).parent / 'fixtures' / filename).read_text())
    assert rs.compute_asr(report) == asr
    assert rs.evaluate_policy(report, 5, set()) is violation
    if filename.startswith('static'):
        assert rs.evaluate_policy(report, 5, {'PROMPT_INJECTION'})
