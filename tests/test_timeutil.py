import unittest
from datetime import datetime

from core import timeutil as t


class TimeUtilTests(unittest.TestCase):
    def test_filetime_unix_epoch(self):
        # 1970-01-01 expressed as FILETIME
        self.assertEqual(t.to_iso(t.filetime_to_utc(116444736000000000)), "1970-01-01T00:00:00Z")

    def test_filetime_zero_and_never(self):
        self.assertIsNone(t.filetime_to_utc(0))
        self.assertIsNone(t.filetime_to_utc(0x7FFFFFFFFFFFFFFF))  # "never"

    def test_webkit_unix_epoch(self):
        self.assertEqual(t.to_iso(t.webkit_to_utc(11644473600000000)), "1970-01-01T00:00:00Z")

    def test_unix(self):
        self.assertEqual(t.to_iso(t.unix_to_utc(86400)), "1970-01-02T00:00:00Z")

    def test_unix_micro(self):
        self.assertEqual(t.to_iso(t.unix_micro_to_utc(86400 * 1_000_000)), "1970-01-02T00:00:00Z")

    def test_iso_text_seven_digit_fraction(self):
        self.assertEqual(t.to_iso(t.iso_text_to_utc("2026-10-22T04:35:10.1234567Z")), "2026-10-22T04:35:10Z")

    def test_iso_text_plain_z_and_no_zone(self):
        self.assertEqual(t.to_iso(t.iso_text_to_utc("2026-10-22T04:35:10Z")), "2026-10-22T04:35:10Z")
        self.assertEqual(t.to_iso(t.iso_text_to_utc("2026-10-22T04:35:10")), "2026-10-22T04:35:10Z")

    def test_iso_text_garbage(self):
        self.assertIsNone(t.iso_text_to_utc("not a date"))
        self.assertIsNone(t.iso_text_to_utc(""))

    def test_local_ist_to_utc(self):
        # 10:00 IST is 04:30 UTC
        self.assertEqual(t.to_iso(t.local_text_to_utc("2026-10-22 10:00:00")), "2026-10-22T04:30:00Z")

    def test_ist_display(self):
        self.assertEqual(t.iso_to_ist_text("2026-10-22T04:30:00Z"), "2026-10-22 10:00:00")

    def test_to_iso_rejects_naive(self):
        with self.assertRaises(ValueError):
            t.to_iso(datetime(2026, 1, 1))

    def test_to_iso_none(self):
        self.assertEqual(t.to_iso(None), "")


if __name__ == "__main__":
    unittest.main()
