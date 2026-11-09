"""Regression tests for problems found when the parsers first ran on the real Windows 11 evidence."""
import struct
from datetime import datetime, timezone

from core.schema import Event
from parsers.evtx import _drop_linked_logons, _event_from_xml
from parsers.recyclebin import parse

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
SEC = "Microsoft-Windows-Security-Auditing"


def _logon(logon_id, linked, user="admin", ts="2026-10-31T05:14:00Z"):
    return Event(timestamp_utc=ts, time_meaning="logon", source="EventLog", event_type="USER_LOGON",
                 user=user, summary=f"User {user} logged on (interactive)",
                 details={"logon_id": logon_id, "linked_logon_id": linked})


# ---- Windows 11 writes two linked 4624 records for one admin logon -------------
def test_linked_logon_pair_collapsed_to_one():
    pair = [_logon("0xc484a", "0xc488f"), _logon("0xc488f", "0xc484a")]
    assert len(_drop_linked_logons(pair)) == 1
    assert _drop_linked_logons(pair)[0].details["logon_id"] == "0xc484a"


def test_separate_logons_are_both_kept():
    null = "0x0000000000000000"
    two = [_logon("0x111", null, ts="2026-10-31T05:14:00Z"), _logon("0x222", null, ts="2026-10-31T09:00:00Z")]
    assert len(_drop_linked_logons(two)) == 2


def test_non_logon_events_untouched():
    other = Event("2026-10-31T05:14:00Z", "created", "EventLog", "ACCOUNT_CREATED", "ravi", "x", {})
    assert _drop_linked_logons([other, other]) == [other, other]


def test_linked_logon_id_is_stored_from_xml():
    data = ('<Data Name="TargetUserName">admin</Data><Data Name="TargetDomainName">PC</Data>'
            '<Data Name="LogonType">2</Data><Data Name="TargetLogonId">0xc484a</Data>'
            '<Data Name="TargetLinkedLogonId">0xc488f</Data>')
    x = (f'<Event {NS}><System><Provider Name="{SEC}"/><EventID>4624</EventID>'
         '<TimeCreated SystemTime="2026-10-31 05:14:00.134455"/><EventRecordID>1</EventRecordID>'
         f"</System><EventData>{data}</EventData></Event>")
    e = _event_from_xml(x, "security", "Logs/Security.evtx")
    assert e.details["linked_logon_id"] == "0xc488f"


# ---- accounts created by the machine during Windows setup are not user actions ---
def _created(by):
    data = f'<Data Name="TargetUserName">admin</Data><Data Name="SubjectUserName">{by}</Data>'
    x = (f'<Event {NS}><System><Provider Name="{SEC}"/><EventID>4720</EventID>'
         '<TimeCreated SystemTime="2026-10-31T05:13:10Z"/><EventRecordID>1</EventRecordID>'
         f"</System><EventData>{data}</EventData></Event>")
    return _event_from_xml(x, "security", "Logs/Security.evtx")


def test_account_created_by_machine_is_flagged():
    assert _created("WIN11-EVIDENCE$").details["created_by_machine"] is True
    assert _created("admin").details["created_by_machine"] is False


# ---- "$I30" (NTFS index file) must not be read as a Recycle Bin file ------------
def test_i30_files_ignored_everywhere(tmp_path):
    ntfs_index = bytes.fromhex("494e445828000900") + b"\x00" * 4088
    for folder in ("RecycleBin/$Recycle.Bin/S-1-5-21-1-2-3-1001", "Prefetch", "Logs"):
        d = tmp_path / folder
        d.mkdir(parents=True)
        (d / "$I30").write_bytes(ntfs_index)
    assert parse(str(tmp_path)) == []


def test_real_style_name_still_parsed(tmp_path):
    d = tmp_path / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
    d.mkdir(parents=True)
    path = r"C:\Users\ravi\Documents\client_list.csv"
    when = datetime(2026, 11, 1, 8, 43, 22, tzinfo=timezone.utc)
    ft = int((when - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000
    (d / "$IBLKUJ7.csv").write_bytes(
        struct.pack("<QQQI", 2, 37, ft, len(path) + 1) + (path + "\x00").encode("utf-16-le"))
    assert parse(str(tmp_path))[0].timestamp_utc == "2026-11-01T08:43:22Z"
