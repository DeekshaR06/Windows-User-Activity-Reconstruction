import csv
import os
import tempfile
import unittest

from analysis import rules, sessions
from core import timeline
from report import html_timeline as ht

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo", "fake_events.csv")


def make_outputs(folder):
    events, _ = timeline.build(timeline.read_csv(DEMO))
    s = sessions.build_sessions(events)
    f = rules.run_all(events, s)
    paths = {k: os.path.join(folder, k + ".csv") for k in ("timeline", "findings", "sessions")}
    timeline.write_csv(events, paths["timeline"])
    rules.write_csv(f, paths["findings"])
    sessions.write_csv(s, paths["sessions"])
    return paths, events, f


class HtmlViewerTests(unittest.TestCase):
    def test_page_is_built_and_self_contained(self):
        with tempfile.TemporaryDirectory() as d:
            p, events, _ = make_outputs(d)
            out = ht.write(os.path.join(d, "t.html"), p["timeline"], p["findings"], p["sessions"])
            with open(out, encoding="utf-8") as fh:
                text = fh.read()
        self.assertTrue(text.startswith("<!doctype html>"))
        self.assertNotIn("<script src", text)          # no outside libraries
        self.assertNotIn("http://", text.split("const DATA")[0])
        self.assertIn("Possible data copy via USB", text)

    def test_every_finding_links_back_to_its_events(self):
        with tempfile.TemporaryDirectory() as d:
            p, events, findings = make_outputs(d)
            payload = ht.build_payload(ht._read_csv(p["timeline"]), ht._read_csv(p["findings"]),
                                       ht._read_csv(p["sessions"]))
        self.assertEqual(len(payload["findings"]), len(findings))
        for shown, real in zip(payload["findings"], findings):
            self.assertEqual(len(shown["rows"]), len(real.evidence), real.rule_id)

    def test_evidence_cannot_break_out_of_the_page(self):
        evil = [{"timestamp_ist": "2026-10-22 10:00:00", "timestamp_utc": "2026-10-22T04:30:00Z",
                 "source": "Browser", "event_type": "URL_VISITED", "user": "x",
                 "summary": "</script><script>alert(1)</script><!-- x", "time_meaning": "visited",
                 "details": "{}", "evidence_file": "a"}]
        text = ht.render(ht.build_payload(evil))
        self.assertNotIn("</script><script>alert(1)", text)
        self.assertEqual(text.count("</script>"), 1)    # only the page's own closing tag
        self.assertNotIn("<!-- x", text)

    def test_empty_timeline_still_builds(self):
        text = ht.render(ht.build_payload([]))
        self.assertIn("<!doctype html>", text)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p, _, _ = make_outputs(d)
            out = os.path.join(d, "x.html")
            rc = ht.main(["--timeline", p["timeline"], "--findings", p["findings"],
                          "--sessions", p["sessions"], "--out", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.getsize(out) > 5000)
            self.assertEqual(ht.main(["--timeline", os.path.join(d, "missing.csv"), "--out", out]), 2)


if __name__ == "__main__":
    unittest.main()
