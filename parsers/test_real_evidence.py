"""Real-evidence checks for Member 2's parsers.

These run ONLY if Member 1's evidence is on your computer, and are skipped
otherwise, so they never break anyone else's test run. Evidence itself must
never be committed to Git.

Put the unzipped package so that these two folders exist:
    evidence/export/Prefetch/
    evidence/export/Recent/
or point to it:  set EVIDENCE_DIR=C:\\path\\to\\Member_2   (PowerShell: $env:EVIDENCE_DIR="...")
"""
import logging
import os
import unittest

from parsers import lnk, prefetch

EVIDENCE = os.environ.get("EVIDENCE_DIR") or os.path.join("evidence", "export")
HAVE_EVIDENCE = (os.path.isdir(os.path.join(EVIDENCE, "Prefetch"))
                 and os.path.isdir(os.path.join(EVIDENCE, "Recent")))


@unittest.skipUnless(HAVE_EVIDENCE, "real evidence not found (see the note at the top of this file)")
class RealEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.disable(logging.WARNING)  # empty files / 1980 placeholders warn on purpose
        cls.pf = prefetch.parse(EVIDENCE)
        cls.ln = lnk.parse(EVIDENCE)

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)

    def test_every_event_passes_the_schema_check(self):
        for e in self.pf + self.ln:
            self.assertTrue(e.is_valid(), (e.problems(), e.summary))

    def test_no_placeholder_dates_leak_into_the_timeline(self):
        for e in self.pf + self.ln:
            self.assertGreaterEqual(e.timestamp_utc[:4], "2000", e.summary)

    def test_scenario_programs_are_found_in_prefetch(self):
        names = {e.details["executable"].upper() for e in self.pf}
        for wanted in ("NOTEPAD.EXE", "MSEDGE.EXE", "CALCULATORAPP.EXE", "MSPAINT.EXE", "CMD.EXE"):
            self.assertIn(wanted, names)
        self.assertTrue(any(n.startswith("7Z") for n in names), "installer (7-Zip) not found")

    def test_prefetch_events_carry_proof_and_run_count(self):
        for e in self.pf:
            self.assertEqual(e.event_type, "PROGRAM_EXECUTED")
            self.assertTrue(e.evidence_file.startswith("Prefetch/"))
            self.assertGreaterEqual(e.details["run_count"], 1)

    def test_pen_drive_file_shortcut_is_flagged_removable(self):
        usb = [e for e in self.ln if e.details["target_path"].lower().endswith("client_list.csv")]
        self.assertEqual(len(usb), 1)
        self.assertTrue(usb[0].details["removable"])
        self.assertIn("[REMOVABLE DRIVE]", usb[0].summary)

    def test_normal_disk_shortcuts_are_not_flagged(self):
        normal = [e for e in self.ln if e.details["target_path"].upper().startswith("C:\\")]
        self.assertTrue(normal)
        for e in normal:
            self.assertFalse(e.details["removable"])


if __name__ == "__main__":
    unittest.main()
