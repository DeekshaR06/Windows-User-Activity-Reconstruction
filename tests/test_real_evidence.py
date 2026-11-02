"""Integration tests on the real Windows 11 VM evidence (export2.zip from Member 1).

Skipped automatically when the evidence folder is not on this machine (evidence is never in Git).
Point to it with the EVIDENCE_DIR environment variable, default: evidence/export
"""
import collections
import os

import pytest

from parsers import evtx, recyclebin

EVIDENCE = os.environ.get("EVIDENCE_DIR", "evidence/export")
pytestmark = pytest.mark.skipif(not os.path.isdir(EVIDENCE), reason="real evidence folder not available")

RAVI_SID = "S-1-5-21-3876880713-1864589280-3295052806-1001"


@pytest.fixture(scope="module")
def log_events():
    return evtx.parse(EVIDENCE)


@pytest.fixture(scope="module")
def deleted():
    return recyclebin.parse(EVIDENCE)


def test_every_event_is_valid_utc(log_events, deleted):
    for e in log_events + deleted:
        assert e.timestamp_utc.endswith("Z") and len(e.timestamp_utc) == 20
        assert e.summary and e.evidence_file


def test_ravi_account_created_by_admin(log_events):
    made = [e for e in log_events if e.event_type == "ACCOUNT_CREATED" and e.user == "ravi"]
    assert len(made) == 1
    assert made[0].details["created_by"] == "admin"
    assert made[0].details["new_user_sid"] == RAVI_SID


def test_logon_sessions_not_duplicated(log_events):
    logons = collections.Counter(e.user for e in log_events if e.event_type == "USER_LOGON")
    assert logons["ravi"] == 3   # 2 sessions on 31 Oct (+1 re-logon) and 1 on 1 Nov, one record each
    assert logons["admin"] == 5


def test_no_service_account_logons(log_events):
    users = {e.user for e in log_events if e.event_type == "USER_LOGON"}
    assert users == {"admin", "ravi"}


def test_application_log_cleared_by_ravi_in_both_sessions(log_events):
    cleared = [e for e in log_events if e.event_type == "LOG_CLEARED"]
    assert len(cleared) == 2
    assert all(e.user == "ravi" and e.details["channel"] == "Application" for e in cleared)
    assert cleared[-1].timestamp_utc == "2026-11-01T08:45:57Z"


def test_wevtutil_start_matches_log_cleared_time(log_events):
    run = [e for e in log_events if e.event_type == "PROGRAM_EXECUTED"
           and e.details["path"].lower().endswith("wevtutil.exe") and e.timestamp_utc.startswith("2026-11-01")]
    assert run and run[0].timestamp_utc == "2026-11-01T08:45:57Z"


def test_clean_shutdown_at_end(log_events):
    assert log_events[-1].event_type == "SYSTEM_SHUTDOWN"
    assert log_events[-1].timestamp_utc == "2026-11-01T08:49:00Z"


def test_four_deleted_files(deleted):
    assert len(deleted) == 4
    assert collections.Counter(e.summary.split(" deleted")[0] for e in deleted) == {
        "client_list.csv": 2, "salary_report.txt": 2}
    assert all(e.details["sid"] == RAVI_SID and e.details["r_file_present"] for e in deleted)


def test_main_run_deletions_on_1_nov(deleted):
    main_run = [e for e in deleted if e.timestamp_utc.startswith("2026-11-01")]
    assert {e.timestamp_utc for e in main_run} == {"2026-11-01T08:43:22Z"}
