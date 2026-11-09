import os
import tempfile
import unittest

from parsers import prefetch


class PrefetchParserTest(unittest.TestCase):
    def test_empty_folder_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(prefetch.parse(d), [])

    def test_corrupt_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Prefetch"))
            with open(os.path.join(d, "Prefetch", "BAD.EXE-00000000.pf"), "wb") as f:
                f.write(b"this is not a prefetch file")
            self.assertEqual(prefetch.parse(d), [])

    def test_empty_file_is_skipped_with_clear_message(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Prefetch"))
            open(os.path.join(d, "Prefetch", "EMPTY.EXE-00000000.pf"), "wb").close()
            with self.assertLogs("parsers.prefetch", level="WARNING") as cm:
                self.assertEqual(prefetch.parse(d), [])
            self.assertIn("empty (0 bytes)", cm.output[0])
            self.assertIn("Prefetch/EMPTY.EXE-00000000.pf", cm.output[0])

    def test_uppercase_pf_extension_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Prefetch"))
            open(os.path.join(d, "Prefetch", "ABC~1.PF"), "wb").close()
            with self.assertLogs("parsers.prefetch", level="WARNING") as cm:
                prefetch.parse(d)
            self.assertIn("ABC~1.PF", cm.output[0])


if __name__ == "__main__":
    unittest.main()
