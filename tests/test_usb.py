import os
import tempfile
import unittest

from parsers.usb import parse


class USBParserTests(unittest.TestCase):
    def test_setupapi_usb_device(self):
        with tempfile.TemporaryDirectory() as root:
            folder = os.path.join(root, "Registry")
            os.makedirs(folder)

            log_path = os.path.join(folder, "setupapi.dev.log")

            with open(log_path, "w", encoding="utf-8") as f:
                f.write(
                    ">>>  Section start 2026/10/22 10:15:00.000\n"
                    ">>> [Device Install (Hardware initiated)]\n"
                    "     USB\\VID_1234&PID_5678\\ABC123\n"
                )

            events = parse(root)

            self.assertGreaterEqual(len(events), 1)
            self.assertTrue(
                any("VID_1234" in e.summary for e in events)
            )
            self.assertTrue(all(e.is_valid() for e in events))

    def test_missing_folder(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(parse(root), [])


if __name__ == "__main__":
    unittest.main()
