import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from core import timeutil
from parsers.browser import parse

class BrowserParserTests(unittest.TestCase):
    def test_history_and_download(self):
        with tempfile.TemporaryDirectory() as root:
            folder = os.path.join(root, "Browser")
            os.makedirs(folder)
            path = os.path.join(folder, "History")
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
                CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
                CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, tab_url TEXT, site_url TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER);
            """)
            # 2026-10-22 00:00 UTC as WebKit microseconds
            dt = datetime(2026,10,22,tzinfo=timezone.utc)
            webkit = int((dt - datetime(1601,1,1,tzinfo=timezone.utc)).total_seconds() * 1_000_000)
            conn.execute("INSERT INTO urls VALUES(1,?,?,1,?)", ("https://example.com", "Example", webkit))
            conn.execute("INSERT INTO visits VALUES(1,1,?)", (webkit,))
            conn.execute("INSERT INTO downloads VALUES(1,'','C:/Downloads/a.zip','https://example.com','https://example.com',?, ?,100,100,1)", (webkit,webkit))
            conn.commit(); conn.close()
            events = parse(root)
            self.assertEqual({e.event_type for e in events}, {"URL_VISITED", "FILE_DOWNLOADED"})
            self.assertTrue(all(e.is_valid() for e in events))
            self.assertTrue(all(e.evidence_file == "Browser/History" for e in events))

    def test_missing_folder(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(parse(root), [])

if __name__ == "__main__":
    unittest.main()
