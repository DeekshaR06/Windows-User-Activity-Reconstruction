from parsers.evtx import _event_from_xml

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def _xml(eid, provider, stamp, data="", channel="Security", userdata=""):
    return (
        f'<Event {NS}><System><Provider Name="{provider}"/><EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{stamp}"/><EventRecordID>7</EventRecordID>'
        f"<Channel>{channel}</Channel></System>"
        f"<EventData>{data}</EventData>{userdata}</Event>"
    )


def _logon(user, domain, ltype):
    return (f'<Data Name="TargetUserName">{user}</Data>'
            f'<Data Name="TargetDomainName">{domain}</Data>'
            f'<Data Name="LogonType">{ltype}</Data>')


def test_real_logon_kept():
    x = _xml(4624, "Microsoft-Windows-Security-Auditing", "2026-10-22 04:35:10.123456", _logon("ravi", "PC", 2))
    e = _event_from_xml(x, "security", "Security.evtx")
    assert e.event_type == "USER_LOGON" and e.user == "ravi"
    assert e.timestamp_utc == "2026-10-22T04:35:10Z"


def test_dwm_and_service_logons_skipped():
    x = _xml(4624, "Microsoft-Windows-Security-Auditing", "2026-10-22T04:35:10.1234567Z",
             _logon("DWM-1", "Window Manager", 2))
    assert _event_from_xml(x, "security", "Security.evtx") is None
    x = _xml(4624, "Microsoft-Windows-Security-Auditing", "2026-10-22T04:35:10Z", _logon("ravi", "PC", 5))
    assert _event_from_xml(x, "security", "Security.evtx") is None


def test_log_cleared_104():
    ud = ('<UserData><LogFileCleared xmlns="http://schemas.microsoft.com/win/2004/08/events/eventlog">'
          "<SubjectUserName>ravi</SubjectUserName><Channel>Application</Channel></LogFileCleared></UserData>")
    x = _xml(104, "Microsoft-Windows-Eventlog", "2026-10-22T05:20:00Z", channel="System", userdata=ud)
    e = _event_from_xml(x, "system", "System.evtx")
    assert e.event_type == "LOG_CLEARED" and e.details["channel"] == "Application" and e.user == "ravi"


def test_shutdown_6006():
    x = _xml(6006, "EventLog", "2026-10-22T06:00:00Z", channel="System")
    assert _event_from_xml(x, "system", "System.evtx").event_type == "SYSTEM_SHUTDOWN"
