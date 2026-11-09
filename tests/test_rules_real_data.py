"""Rule checks for what the REAL parsers put in their events (found when validating
against the ground truth): LNK says drive_type "DRIVE_REMOVABLE" + removable=True,
repeat downloads are named "name (1).exe", Edge's updater runs from a Temp folder."""
import unittest

from analysis import rules
from core.schema import Event


def ev(utc, source, etype, summary, details=None, user="ravi"):
    return Event(timestamp_utc=utc, time_meaning="test", source=source, event_type=etype,
                 user=user, summary=summary, details=details or {}, evidence_file="x")


class RealDataRulesTest(unittest.TestCase):
    def test_r1_fires_for_lnk_drive_removable(self):
        events = [
            ev("2026-11-01T08:37:16Z", "USB", "USB_CONNECTED", "USB disk connected: VendorCo ProductCode"),
            ev("2026-11-01T08:41:00Z", "LNK", "FILE_OPENED", "F:\\ opened [REMOVABLE DRIVE]",
               {"drive_type": "DRIVE_REMOVABLE", "removable": True}),
            ev("2026-11-01T08:43:22Z", "RecycleBin", "FILE_DELETED", "client_list.csv deleted"),
            ev("2026-11-01T08:45:57Z", "EventLog", "LOG_CLEARED", "The Application log was cleared by ravi"),
        ]
        found = [f for f in rules.run_all(events) if f.rule_id == "R1"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "High")
        self.assertIn("event log cleared", found[0].description)

    def test_fixed_drive_shortcut_is_not_removable(self):
        e = ev("2026-11-01T08:26:30Z", "LNK", "FILE_OPENED", "notes.txt opened from C:\\Users\\ravi\\notes.txt",
               {"drive_type": "DRIVE_FIXED", "removable": False})
        self.assertFalse(rules._is_removable(e))

    def test_r3_matches_repeat_download_name_with_number(self):
        events = [
            ev("2026-11-01T08:33:00Z", "Browser", "FILE_DOWNLOADED",
               "Downloaded 7z2605-x64 (1).exe from https://7-zip.org/"),
            ev("2026-11-01T08:33:53Z", "EventLog", "PROGRAM_EXECUTED", "7z2605-x64 (1).exe was started by ravi"),
        ]
        found = [f for f in rules.run_all(events) if f.rule_id == "R3"]
        self.assertEqual(len(found), 1)
        self.assertIn("7z2605-x64 (1).exe", found[0].description)

    def test_r4_ignores_edge_updater(self):
        events = [ev("2026-10-31T05:16:06Z", "Prefetch", "PROGRAM_EXECUTED",
                     "MICROSOFTEDGEUPDATE.EXE was run (run count 1)",
                     {"files": ["\\USERS\\ADMIN\\APPDATA\\LOCAL\\TEMP\\X.TMP"]}, user="")]
        self.assertEqual([f for f in rules.run_all(events) if f.rule_id == "R4"], [])

    def test_r4_still_flags_installer_in_downloads(self):
        events = [ev("2026-11-01T08:33:53Z", "EventLog", "PROGRAM_EXECUTED",
                     "7z2605-x64 (1).exe was started by ravi",
                     {"path": "C:\\Users\\ravi\\Downloads\\7z2605-x64 (1).exe"})]
        self.assertEqual(len([f for f in rules.run_all(events) if f.rule_id == "R4"]), 1)


if __name__ == "__main__":
    unittest.main()
