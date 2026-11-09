"""Builds a tiny but valid .lnk file in memory, so tests do not need real evidence."""
import struct
from datetime import datetime, timezone

DRIVE_REMOVABLE, DRIVE_FIXED = 2, 3


def _ft(dt):
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


def build_lnk(base_path, suffix, accessed, size=1234, drive_type=DRIVE_REMOVABLE, serial=0xAABBCCDD,
              created=None, modified=None):
    created = created or accessed
    modified = modified or accessed
    header = struct.pack(
        "<I16sIIQQQIIIHHII",
        0x4C,
        b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46",
        0x2,                       # LinkFlags: HasLinkInfo
        0x20,                      # FILE_ATTRIBUTE_ARCHIVE
        _ft(created), _ft(accessed), _ft(modified),
        size, 0, 1, 0, 0, 0, 0,
    )
    label = b"USB\x00"
    vol = struct.pack("<IIII", 0x10 + len(label), drive_type, serial, 0x10) + label
    base = base_path.encode("cp1252") + b"\x00"
    suf = suffix.encode("cp1252") + b"\x00"
    hdr_len = 0x1C
    vol_off = hdr_len
    base_off = vol_off + len(vol)
    suf_off = base_off + len(base)
    total = suf_off + len(suf)
    info = struct.pack("<IIIIIII", total, hdr_len, 0x1, vol_off, base_off, 0, suf_off) + vol + base + suf
    return header + info
