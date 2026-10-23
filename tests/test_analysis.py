import os
import unittest

from analysis import rules, sessions
from core import timeline
from core.schema import Event

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo", "fake_events.csv")


def T(h, m, s=0):
    return "2026-10-22T%02d:%02d:%02dZ" % (h, m, s)


def ev(ts, etype, summary="x", source="EventLog", user="ravi", details=None):
    return Event(timestamp_utc=ts, time_meaning="t", source=source, event_type=etype,
                 user=user, summary=summary, details=details or {})


class SessionTests(unittest.TestCase):
    def test_logon_logoff(self):
        s = sessions.build_sessions([ev(T(4, 0), "USER_LOGON"), ev(T(4, 30), "PROGRAM_EXECUTED"),
                                     ev(T(5, 0), "USER_LOGOFF")])
        self.assertEqual(len(s), 1)
        self.assertEqual((s[0].start_utc, s[0].end_utc, s[0].ended_by), (T(4, 0), T(5, 0), "logoff"))
        self.assertEqual(s[0].event_count, 3)

    def test_shutdown_closes_open_session(self):
        s = sessions.build_sessions([ev(T(4, 0), "USER_LOGON"), ev(T(6, 0), "SYSTEM_SHUTDOWN", user="")])
        self.assertEqual(s[0].ended_by, "shutdown")

    def test_open_session_ends_at_last_event(self):
        s = sessions.build_sessions([ev(T(4, 0), "USER_LOGON"), ev(T(4, 20), "PROGRAM_EXECUTED")])
        self.assertEqual((s[0].end_utc, s[0].ended_by), (T(4, 20), "end of data"))

    def test_new_logon_closes_previous(self):
        s = sessions.build_sessions([ev(T(4, 0), "USER_LOGON"), ev(T(5, 0), "USER_LOGON")])
        self.assertEqual(len(s), 2)
        self.assertEqual(s[0].ended_by, "new logon")

    def test_two_users_are_separate(self):
        s = sessions.build_sessions([ev(T(4, 0), "USER_LOGON", user="a"), ev(T(4, 5), "USER_LOGON", user="b"),
                                     ev(T(4, 10), "USER_LOGOFF", user="a")])
        self.assertEqual({x.user for x in s}, {"a", "b"})
        self.assertEqual(sessions.session_for(s, "a", T(4, 6)), 1)

    def test_empty(self):
        self.assertEqual(sessions.build_sessions([]), [])


class RuleTests(unittest.TestCase):
    def ids(self, events, **kw):
        return [f.rule_id for f in rules.run_all(events, **kw)]

    def usb_story(self, drive="removable", open_minute=3):
        return [ev(T(4, 0), "USB_CONNECTED", "USB device X connected", "USB"),
                ev(T(4, open_minute), "FILE_OPENED", "Opened a.csv from drive E:", "LNK", details={"drive_type": drive})]

    def test_r1_fires_for_removable_open(self):
        f = [x for x in rules.run_all(self.usb_story()) if x.rule_id == "R1"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "High")
        self.assertEqual(len(f[0].evidence), 2)

    def test_r1_not_for_fixed_drive(self):
        self.assertNotIn("R1", self.ids(self.usb_story(drive="fixed")))

    def test_r1_not_after_30_minutes(self):
        self.assertNotIn("R1", self.ids(self.usb_story(open_minute=45)))

    def test_r1_mentions_deletion_and_log_clear(self):
        evs = self.usb_story() + [ev(T(4, 10), "FILE_DELETED", "Deleted a.csv", "RecycleBin"),
                                  ev(T(4, 12), "LOG_CLEARED", "Application log was cleared")]
        r1 = [x for x in rules.run_all(evs) if x.rule_id == "R1"][0]
        self.assertIn("deleted", r1.description)
        self.assertIn("cleared", r1.description)
        self.assertEqual(len(r1.evidence), 4)

    def test_r1_removable_detected_from_summary_when_no_details(self):
        evs = [ev(T(4, 0), "USB_CONNECTED", "USB connected", "USB"),
               ev(T(4, 2), "FILE_OPENED", "Opened a.csv from drive E: (removable)", "LNK")]
        self.assertIn("R1", self.ids(evs))

    def test_r2_one_finding_for_one_deletion_burst(self):
        evs = [ev(T(4, 0), "USB_CONNECTED", "c", "USB"), ev(T(4, 5), "USB_REMOVED", "r", "USB"),
               ev(T(4, 10), "FILE_DELETED", "d1", "RecycleBin"), ev(T(4, 11), "FILE_DELETED", "d2", "RecycleBin")]
        self.assertEqual(self.ids(evs).count("R2"), 1)

    def test_r2_not_when_deleted_long_after(self):
        evs = [ev(T(4, 0), "USB_CONNECTED", "c", "USB"), ev(T(6, 0), "FILE_DELETED", "d", "RecycleBin")]
        self.assertNotIn("R2", self.ids(evs))

    def test_r3_download_then_run_case_insensitive(self):
        evs = [ev(T(4, 0), "FILE_DOWNLOADED", "Downloaded 7z-setup.exe to C:\\Users\\x\\Downloads", "Browser"),
               ev(T(4, 5), "PROGRAM_EXECUTED", "7Z-SETUP.EXE was run", "Prefetch")]
        self.assertIn("R3", self.ids(evs))

    def test_r3_other_program_or_too_late(self):
        evs = [ev(T(4, 0), "FILE_DOWNLOADED", "Downloaded a.exe", "Browser"),
               ev(T(4, 5), "PROGRAM_EXECUTED", "B.EXE was run", "Prefetch"),
               ev(T(4, 30), "PROGRAM_EXECUTED", "A.EXE was run", "Prefetch")]
        self.assertNotIn("R3", self.ids(evs))

    def test_r4_risky_location(self):
        self.assertIn("R4", self.ids([ev(T(4, 0), "PROGRAM_EXECUTED", "X.EXE was run from Downloads", "Prefetch")]))
        self.assertIn("R4", self.ids([ev(T(4, 0), "PROGRAM_EXECUTED", "run", "Prefetch",
                                         details={"path": "C:\\Users\\a\\AppData\\Local\\Temp\\x.exe"})]))
        self.assertNotIn("R4", self.ids([ev(T(4, 0), "PROGRAM_EXECUTED", "NOTEPAD.EXE was run", "Prefetch")]))

    def test_r5_log_cleared_is_high(self):
        f = rules.run_all([ev(T(4, 0), "LOG_CLEARED", "Application log was cleared")])
        self.assertEqual([(x.rule_id, x.severity) for x in f], [("R5", "High")])

    def test_r6_account_then_logon(self):
        evs = [ev(T(4, 0), "ACCOUNT_CREATED", "created"), ev(T(5, 0), "USER_LOGON", "logon")]
        self.assertIn("R6", self.ids(evs))

    def test_r6_not_after_two_days(self):
        evs = [ev("2026-10-20T04:00:00Z", "ACCOUNT_CREATED", "created"), ev("2026-10-22T05:00:00Z", "USER_LOGON", "l")]
        self.assertNotIn("R6", self.ids(evs))

    def test_r7_off_by_default_and_on_when_asked(self):
        late = [ev(T(20, 0), "PROGRAM_EXECUTED", "x", "Prefetch")]       # 01:30 IST next day
        self.assertNotIn("R7", self.ids(late))
        self.assertIn("R7", self.ids(late, working_hours=(9, 18)))

    def test_no_events_no_findings(self):
        self.assertEqual(rules.run_all([]), [])

    def test_sorted_high_first_and_ids_numbered(self):
        evs = [ev(T(4, 0), "ACCOUNT_CREATED", "c"), ev(T(4, 1), "USER_LOGON", "l"), ev(T(4, 2), "LOG_CLEARED", "x")]
        f = rules.run_all(evs)
        self.assertEqual(f[0].severity, "High")
        self.assertEqual([x.finding_id for x in f], list(range(1, len(f) + 1)))


class DemoDataTests(unittest.TestCase):
    def test_demo_story_is_found(self):
        events, _ = timeline.build(timeline.read_csv(DEMO))
        s = sessions.build_sessions(events)
        f = rules.run_all(events, s)
        got = {x.rule_id for x in f}
        self.assertEqual(got, {"R1", "R2", "R3", "R4", "R5", "R6"})
        self.assertEqual(f[0].rule_id in ("R1", "R5"), True)          # a High finding comes first
        r1 = [x for x in f if x.rule_id == "R1"][0]
        self.assertEqual(r1.session_id, 1)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0].ended_by, "logoff")


if __name__ == "__main__":
    unittest.main()
