"""
Unit tests for redteam_scan.py.

Run with: pytest -v test_redteam_scan.py

Fixtures mirror the verified @cdot65/prisma-airs-sdk 0.11.0 report shapes:
  - ASR ("asr") is a 0..1 ratio.
  - Static reports nest categories under security_report / safety_report /
    brand_report (sub_categories[].successful) and compliance_report[].
"""
import json
from unittest.mock import MagicMock, patch

import pytest

import redteam_scan as rs


# --- normalize_job_type ----------------------------------------------------


@pytest.mark.parametrize(
    "scan_type,expected",
    [
        ("STATIC", "STATIC"),
        ("static", "STATIC"),
        ("DYNAMIC", "DYNAMIC"),
        ("ATTACK_LIBRARY", "STATIC"),  # legacy alias maps to STATIC
        ("CUSTOM", "CUSTOM"),
    ],
)
def test_normalize_job_type(scan_type, expected):
    assert rs.normalize_job_type(scan_type) == expected


# --- build_job_metadata ----------------------------------------------------


def test_build_job_metadata_static_selects_all_categories():
    assert rs.build_job_metadata("STATIC") == {"categories": {}}


def test_build_job_metadata_dynamic_is_empty():
    assert rs.build_job_metadata("DYNAMIC") == {}


# --- build_static_categories ----------------------------------------------

_FAKE_CATEGORIES = [
    {"id": "SECURITY", "sub_categories": [{"id": "PROMPT_INJECTION"}, {"id": "JAILBREAK"}]},
    {"id": "SAFETY", "sub_categories": [{"id": "SELF_HARM"}, {"id": "BIAS"}]},
    {"id": "EMPTY", "sub_categories": []},
]


@patch("redteam_scan.list_categories", return_value=_FAKE_CATEGORIES)
def test_build_static_categories_all_by_default(_mock):
    result = rs.build_static_categories("https://data.test", {})
    assert result == {
        "SECURITY": ["PROMPT_INJECTION", "JAILBREAK"],
        "SAFETY": ["SELF_HARM", "BIAS"],
    }  # EMPTY dropped (no subcategories)


@patch("redteam_scan.list_categories", return_value=_FAKE_CATEGORIES)
def test_build_static_categories_select_group(_mock):
    result = rs.build_static_categories("https://data.test", {}, {"SECURITY"})
    assert result == {"SECURITY": ["PROMPT_INJECTION", "JAILBREAK"]}


@patch("redteam_scan.list_categories", return_value=_FAKE_CATEGORIES)
def test_build_static_categories_select_subcategory(_mock):
    result = rs.build_static_categories("https://data.test", {}, {"SELF_HARM"})
    assert result == {"SAFETY": ["SELF_HARM"]}


# --- compute_asr (asr is already a percent in the real API) ----------------


@pytest.mark.parametrize(
    "report,expected",
    [
        ({"asr": 1.09}, 1.09),                  # real golden STATIC report value
        ({"asr": 14.17}, 14.17),                # real golden DYNAMIC report value
        ({"asr": 0.0}, 0.0),
        ({"attack_success_rate": 10.0}, 10.0),
        ({"asr_percent": 3.3}, 3.3),
        ({"stats": {"asr": 1.1}}, 1.1),         # nested
        ({"report_stats": {"asr": 50.0}}, 50.0),
        ({"asr": "7.5"}, 7.5),                  # numeric string
        ({}, None),
        ({"asr": "not-a-number"}, None),
    ],
)
def test_compute_asr_reads_percent(report, expected):
    result = rs.compute_asr(report)
    if expected is None:
        assert result is None
    else:
        assert result == pytest.approx(expected)


# --- successful_category_hits (real static report shape) -------------------


def test_category_hits_from_static_report_subcategories():
    report = {
        "security_report": {
            "id": "SECURITY",
            "display_name": "Security",
            "successful": 3,
            "failed": 10,
            "sub_categories": [
                {"id": "PROMPT_INJECTION", "display_name": "Prompt Injection", "successful": 2, "failed": 4},
                {"id": "JAILBREAK", "display_name": "Jailbreak", "successful": 0, "failed": 6},
            ],
        }
    }
    hits = rs.successful_category_hits(report)
    assert "SECURITY" in hits
    assert "PROMPT_INJECTION" in hits
    assert "PROMPT INJECTION" not in hits       # display_name is NOT indexed (ids only)
    assert "JAILBREAK" not in hits             # zero successes -> not a hit


def test_category_hits_group_with_no_successes_is_absent():
    report = {
        "safety_report": {
            "id": "SAFETY",
            "successful": 0,
            "sub_categories": [
                {"id": "SELF_HARM", "successful": 0, "failed": 3},
            ],
        }
    }
    assert rs.successful_category_hits(report) == set()


def test_category_hits_from_compliance_report():
    report = {
        "compliance_report": [
            {
                "id": "OWASP",
                "display_name": "OWASP",
                "techniques": [
                    {"id": "LLM01", "display_name": "Prompt Injection", "successful": 1},
                    {"id": "LLM02", "successful": 0},
                ],
            }
        ]
    }
    hits = rs.successful_category_hits(report)
    assert "OWASP" in hits
    assert "LLM01" in hits


def test_category_hits_legacy_by_category_list_fallback():
    report = {
        "by_category": [
            {"category": "DLP", "successes": 3},
            {"category": "Toxic", "successes": 0},
        ]
    }
    assert rs.successful_category_hits(report) == {"DLP"}


def test_category_hits_legacy_by_category_dict_fallback():
    report = {"by_category": {"DLP": {"successes": 2}, "PROMPT_INJECTION": {"successes": 0}}}
    assert rs.successful_category_hits(report) == {"DLP"}


def test_category_hits_handles_missing():
    assert rs.successful_category_hits({}) == set()


# --- evaluate_policy -------------------------------------------------------


def test_evaluate_policy_passes_when_below_threshold():
    report = {"asr": 2.0}  # 2% < 5%
    assert rs.evaluate_policy(report, max_asr_percent=5.0, fail_on_categories=set()) is False


def test_evaluate_policy_fails_on_asr_overshoot():
    report = {"asr": 8.0}  # 8% > 5%
    assert rs.evaluate_policy(report, max_asr_percent=5.0, fail_on_categories=set()) is True


def test_evaluate_policy_fails_on_protected_category_hit():
    report = {
        "asr": 1.0,
        "security_report": {
            "id": "SECURITY",
            "successful": 1,
            "sub_categories": [{"id": "PROMPT_INJECTION", "successful": 1}],
        },
    }
    assert rs.evaluate_policy(report, 5.0, {"PROMPT_INJECTION"}) is True


def test_evaluate_policy_passes_when_protected_category_clean():
    report = {
        "asr": 1.0,
        "security_report": {
            "id": "SECURITY",
            "successful": 2,
            "sub_categories": [
                {"id": "PROMPT_INJECTION", "successful": 0},
                {"id": "JAILBREAK", "successful": 2},
            ],
        },
    }
    # JAILBREAK succeeded but is not in the fail-on set; PROMPT_INJECTION is clean.
    assert rs.evaluate_policy(report, 5.0, {"PROMPT_INJECTION"}) is False


def test_evaluate_policy_missing_asr_with_protected_hit_still_fails():
    report = {
        "security_report": {
            "id": "SECURITY",
            "successful": 1,
            "sub_categories": [{"id": "PROMPT_INJECTION", "successful": 1}],
        }
    }
    assert rs.evaluate_policy(report, 5.0, {"PROMPT_INJECTION"}) is True


# --- start_scan (request body + response shape) ----------------------------


@patch("redteam_scan.requests.post")
def test_start_scan_sends_job_create_body(mock_post):
    captured = {}

    def _capture(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return MagicMock(json=lambda: {"uuid": "job-123"}, raise_for_status=lambda: None)

    mock_post.side_effect = _capture
    result = rs.start_scan(
        "https://data.test", {"Authorization": "Bearer t"}, "target-uuid", "STATIC", "my-scan"
    )
    assert result == "job-123"
    assert captured["url"] == "https://data.test/v1/scan"
    body = captured["json"]
    assert body["name"] == "my-scan"
    assert body["target"] == {"uuid": "target-uuid"}
    assert body["job_type"] == "STATIC"
    assert body["job_metadata"] == {"categories": {}}


@patch("redteam_scan.requests.post")
def test_start_scan_returns_uuid_from_various_response_shapes(mock_post):
    for shape in ({"uuid": "abc"}, {"id": "abc"}, {"scan_id": "abc"}):
        mock_post.return_value = MagicMock(
            json=lambda s=shape: s, raise_for_status=lambda: None
        )
        result = rs.start_scan(
            "https://data.test", {"Authorization": "Bearer t"}, "target-uuid", "STATIC", None
        )
        assert result == "abc"


@patch("redteam_scan.requests.post")
def test_start_scan_raises_on_missing_uuid(mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"foo": "bar"}, raise_for_status=lambda: None
    )
    with pytest.raises(RuntimeError, match="no scan identifier"):
        rs.start_scan(
            "https://data.test", {"Authorization": "Bearer t"}, "target-uuid", "STATIC", None
        )


# --- fetch_report (static vs dynamic routing) ------------------------------


@patch("redteam_scan.requests.get")
def test_fetch_report_uses_static_path(mock_get):
    captured = {}

    def _capture(url, headers=None, timeout=None):
        captured["url"] = url
        return MagicMock(json=lambda: {"asr": 0.0}, raise_for_status=lambda: None)

    mock_get.side_effect = _capture
    rs.fetch_report("https://data.test", {}, "job-1", "STATIC")
    assert captured["url"] == "https://data.test/v1/report/static/job-1/report"


@patch("redteam_scan.requests.get")
def test_fetch_report_uses_dynamic_path(mock_get):
    captured = {}

    def _capture(url, headers=None, timeout=None):
        captured["url"] = url
        return MagicMock(json=lambda: {"asr": 0.0}, raise_for_status=lambda: None)

    mock_get.side_effect = _capture
    rs.fetch_report("https://data.test", {}, "job-1", "DYNAMIC")
    assert captured["url"] == "https://data.test/v1/report/dynamic/job-1/report"


# --- poll_until_terminal ---------------------------------------------------


@patch("redteam_scan.time.sleep", return_value=None)
@patch("redteam_scan.get_scan_status")
def test_poll_until_terminal_returns_when_completed(mock_get, _sleep):
    mock_get.side_effect = [
        {"status": "RUNNING", "completed": 1, "total": 10},
        {"status": "RUNNING", "completed": 5, "total": 10},
        {"status": "COMPLETED", "completed": 10, "total": 10},
    ]
    state = rs.poll_until_terminal(
        "https://data.test", {}, "scan-uuid", poll_interval=0, max_wait_minutes=5
    )
    assert state["status"] == "COMPLETED"
    assert mock_get.call_count == 3


@patch("redteam_scan.time.sleep", return_value=None)
@patch("redteam_scan.get_scan_status")
def test_poll_until_terminal_returns_on_partially_complete(mock_get, _sleep):
    mock_get.return_value = {"status": "PARTIALLY_COMPLETE", "completed": 7, "total": 10}
    state = rs.poll_until_terminal(
        "https://data.test", {}, "scan-uuid", poll_interval=0, max_wait_minutes=5
    )
    assert state["status"] == "PARTIALLY_COMPLETE"


@patch("redteam_scan.time.sleep", return_value=None)
@patch("redteam_scan.get_scan_status")
def test_poll_until_terminal_returns_on_failed(mock_get, _sleep):
    mock_get.return_value = {"status": "FAILED", "completed": 3, "total": 10}
    state = rs.poll_until_terminal(
        "https://data.test", {}, "scan-uuid", poll_interval=0, max_wait_minutes=5
    )
    assert state["status"] == "FAILED"


# --- auth ------------------------------------------------------------------


@patch("redteam_scan.requests.post")
def test_fetch_oauth_token_returns_access_token(mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"access_token": "deadbeef"}, raise_for_status=lambda: None
    )
    assert rs.fetch_oauth_token("cid", "csecret", "tsg") == "deadbeef"


@patch("redteam_scan.requests.post")
def test_fetch_oauth_token_raises_when_no_access_token(mock_post):
    mock_post.return_value = MagicMock(json=lambda: {}, raise_for_status=lambda: None)
    with pytest.raises(RuntimeError, match="no access_token"):
        rs.fetch_oauth_token("cid", "csecret", "tsg")


def test_auth_headers_sends_only_bearer():
    headers = rs.auth_headers("tok")
    assert headers["Authorization"] == "Bearer tok"
    assert "x-tsg-id" not in headers  # SDK does not send this


# --- save_report -----------------------------------------------------------


def test_save_report_writes_json(tmp_path):
    target = tmp_path / "report.json"
    rs.save_report({"a": 1, "b": [2, 3]}, str(target))
    with target.open() as fh:
        loaded = json.load(fh)
    assert loaded == {"a": 1, "b": [2, 3]}
