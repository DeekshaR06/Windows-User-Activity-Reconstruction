"""Extra tests for parsers/evtx.py: every event ID we handle, noise filters, bad input, schema contract."""
import re

import pytest

from parsers.evtx import _event_from_xml, parse

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
SEC = "Microsoft-Windows-Security-Auditing"
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _xml(eid, provider, data="", stamp="2026-10-22T04:35:10.000000Z", channel="Security", userdata=""):
    return (
        f'<Event {NS}><System><Provider Name="{provider}"/><EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{stamp}"/><EventRecordID>9</EventRecordID>'
        f"<Channel>{channel}</Channel></System><EventData>{data}</EventData>{userdata}</Event>"
    )


def _d(**kw):
    return "".join(f'<Data Name="{k}">{v}</Data>' for k, v in kw.items())


EL_NS = "http://schemas.microsoft.com/win/2004/08/events/eventlog"


def _cleared(user, channel=None):
    ch = f"<Channel>{channel}</Channel>" if channel else ""
    return (f'<UserData><LogFileCleared xmlns="{EL_NS}"><SubjectUserName>{user}</SubjectUserName>'
            f"{ch}</LogFileCleared></UserData>")


# ---------------------------------------------------------------- handled IDs
def test_logoff_4634_and_4647():
    e = _event_from_xml(_xml(4634, SEC, _d(TargetUserName="ravi", TargetDomainName="PC", LogonType=2)),
                        "security", "Security.evtx")
    assert e.event_type == "USER_LOGOFF" and e.user == "ravi"
    e = _event_from_xml(_xml(4647, SEC, _d(TargetUserName="ravi", TargetDomainName="PC")),
                        "security", "Security.evtx")
    assert e.event_type == "USER_LOGOFF" and "user-initiated" in e.summary


def test_account_created_4720():
    e = _event_from_xml(_xml(4720, SEC, _d(TargetUserName="ravi", SubjectUserName="admin")),
                        "security", "Security.evtx")
    assert e.event_type == "ACCOUNT_CREATED" and e.user == "ravi"
    assert e.details["created_by"] == "admin"


def test_process_created_4688_kept_for_user():
    data = _d(SubjectUserName="ravi", SubjectDomainName="PC", NewProcessName=r"C:\Windows\System32\calc.exe",
              CommandLine="calc.exe", ParentProcessName=r"C:\Windows\explorer.exe", NewProcessId="0x1a4")
    e = _event_from_xml(_xml(4688, SEC, data), "security", "Security.evtx")
    assert e.event_type == "PROGRAM_EXECUTED"
    assert e.summary == "calc.exe was started by ravi"
    assert e.details["path"].endswith("calc.exe")


def test_log_cleared_security_1102():
    e = _event_from_xml(_xml(1102, "Microsoft-Windows-Eventlog", userdata=_cleared("ravi")),
                        "security", "Security.evtx")
    assert e.event_type == "LOG_CLEARED" and e.details["channel"] == "Security" and e.user == "ravi"


def test_system_start_6005():
    e = _event_from_xml(_xml(6005, "EventLog", channel="System"), "system", "System.evtx")
    assert e.event_type == "SYSTEM_START"


# ------------------------------------------------------------------- filters
@pytest.mark.parametrize("user,domain", [
    ("SYSTEM", "NT AUTHORITY"), ("UMFD-0", "Font Driver Host"), ("DWM-2", "Window Manager"),
    ("PC$", "WORKGROUP"), ("ANONYMOUS LOGON", "NT AUTHORITY"),
])
def test_noise_accounts_skipped_for_logon(user, domain):
    x = _xml(4624, SEC, _d(TargetUserName=user, TargetDomainName=domain, LogonType=2))
    assert _event_from_xml(x, "security", "Security.evtx") is None


def test_network_logon_type_3_skipped():
    x = _xml(4624, SEC, _d(TargetUserName="ravi", TargetDomainName="PC", LogonType=3))
    assert _event_from_xml(x, "security", "Security.evtx") is None


def test_4688_by_machine_account_skipped():
    x = _xml(4688, SEC, _d(SubjectUserName="PC$", NewProcessName=r"C:\Windows\System32\svchost.exe"))
    assert _event_from_xml(x, "security", "Security.evtx") is None


def test_104_from_other_provider_ignored():
    x = _xml(104, "SomeApplication", channel="System", userdata=_cleared("ravi", "Application"))
    assert _event_from_xml(x, "system", "System.evtx") is None


def test_unknown_event_id_ignored():
    assert _event_from_xml(_xml(4663, SEC), "security", "Security.evtx") is None


# --------------------------------------------------------------- bad input
def test_empty_folder_returns_empty_list(tmp_path):
    assert parse(str(tmp_path)) == []


def test_corrupt_evtx_does_not_crash(tmp_path):
    (tmp_path / "Security.evtx").write_bytes(b"this is not an evtx file")
    assert parse(str(tmp_path)) == []


# --------------------------------------------------------- schema contract
def test_event_follows_contract():
    e = _event_from_xml(_xml(4624, SEC, _d(TargetUserName="ravi", TargetDomainName="PC", LogonType=2)),
                        "security", "export/Security.evtx")
    assert ISO_RE.match(e.timestamp_utc)
    assert e.source == "EventLog"
    assert e.time_meaning and e.summary and isinstance(e.details, dict)
    assert e.evidence_file == "export/Security.evtx"
    assert e.details["event_id"] == 4624
