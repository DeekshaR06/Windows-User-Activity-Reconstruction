import unittest
from datetime import datetime, timezone

from parsers import usb


def rec(hh, mm, ss, capacity, serial="6255861094384049347"):
    return {"time": datetime(2026, 11, 1, hh, mm, ss, tzinfo=timezone.utc), "capacity": capacity,
            "vendor": "VendorCo", "model": "ProductCode", "serial": serial,
            "disk_number": "1", "parent_id": "USB\\VID_FFFF&PID_5678\\" + serial}


class PartitionUsbEventsTest(unittest.TestCase):
    def test_connect_then_remove(self):
        events = usb._partition_usb_events(
            [rec(8, 37, 16, 4026531840), rec(8, 42, 34, 0)], "Logs/Partition.evtx")
        self.assertEqual([e.event_type for e in events], ["USB_CONNECTED", "USB_REMOVED"])
        self.assertEqual(events[0].timestamp_utc, "2026-11-01T08:37:16Z")
        self.assertEqual(events[1].timestamp_utc, "2026-11-01T08:42:34Z")
        self.assertTrue(all(e.is_valid() for e in events))
        self.assertIn("4.0 GB", events[0].summary)

    def test_boot_time_capacity_zero_record_is_not_a_removal(self):
        # connect, remove, then a capacity-0 record at the next boot (VirtualBox re-attach)
        events = usb._partition_usb_events(
            [rec(8, 37, 16, 4026531840), rec(8, 42, 34, 0), rec(8, 48, 10, 0)], "x")
        self.assertEqual([e.event_type for e in events], ["USB_CONNECTED", "USB_REMOVED"])

    def test_capacity_zero_with_no_earlier_connect_is_ignored(self):
        self.assertEqual(usb._partition_usb_events([rec(8, 48, 10, 0)], "x"), [])

    def test_two_devices_are_tracked_separately(self):
        events = usb._partition_usb_events(
            [rec(8, 37, 16, 4026531840, "AAA"), rec(8, 38, 0, 0, "BBB")], "x")
        self.assertEqual([e.event_type for e in events], ["USB_CONNECTED"])

    def test_order_does_not_matter(self):
        events = usb._partition_usb_events(
            [rec(8, 42, 34, 0), rec(8, 37, 16, 4026531840)], "x")
        self.assertEqual([e.event_type for e in events], ["USB_CONNECTED", "USB_REMOVED"])

    def test_missing_log_folder_gives_no_partition_events(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(usb.parse(d), [])


if __name__ == "__main__":
    unittest.main()
