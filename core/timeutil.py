"""core/timeutil.py -- the ONLY place where time conversion is done.

Every parser must use these functions. Never write your own conversion.
Rule: inside the tool every time is UTC. IST (UTC+05:30) is only for display.

    FILETIME   -> filetime_to_utc()      Prefetch, LNK, Recycle Bin, registry
    WebKit     -> webkit_to_utc()        Edge / Chrome History database
    Unix secs  -> unix_to_utc()          some logs
    ISO text   -> iso_text_to_utc()      Event Log XML ("2026-10-22T04:35:10.123Z")
    Local text -> local_text_to_utc()    setupapi.dev.log (machine local time = IST)

All converters return a timezone-aware datetime in UTC, or None if the input is
empty / zero / out of range (Windows uses 0 or huge numbers for "never").
Use to_iso() to turn the datetime into the string stored in Event.timestamp_utc.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30), "IST")

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
IST_FORMAT = "%Y-%m-%d %H:%M:%S"


def to_iso(dt: Optional[datetime]) -> str:
    """datetime -> 'YYYY-MM-DDTHH:MM:SSZ' (UTC). Returns '' for None."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        raise ValueError("naive datetime: attach a time zone first (see local_text_to_utc)")
    return dt.astimezone(UTC).strftime(ISO_FORMAT)


def filetime_to_utc(filetime: int) -> Optional[datetime]:
    """Windows FILETIME (100-ns steps since 1601-01-01 UTC) -> UTC datetime."""
    if not filetime or filetime < 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except OverflowError:
        return None


def webkit_to_utc(microseconds: int) -> Optional[datetime]:
    """Chrome/Edge 'WebKit time' (microseconds since 1601-01-01 UTC) -> UTC datetime."""
    if not microseconds or microseconds < 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=microseconds)
    except OverflowError:
        return None


def unix_to_utc(seconds: float) -> Optional[datetime]:
    """Unix time (seconds since 1970-01-01 UTC) -> UTC datetime."""
    if seconds is None or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def unix_micro_to_utc(microseconds: int) -> Optional[datetime]:
    """Unix time in microseconds (Firefox) -> UTC datetime."""
    if not microseconds or microseconds <= 0:
        return None
    return unix_to_utc(microseconds / 1_000_000)


_FRACTION = re.compile(r"(\.\d{1,9})")


def iso_text_to_utc(text: str) -> Optional[datetime]:
    """ISO text such as '2026-10-22T04:35:10.1234567Z' -> UTC datetime.

    Text without a zone (no Z / offset) is assumed to already be UTC.
    """
    if not text:
        return None
    s = text.strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    # Event Log gives 7 fractional digits; Python accepts at most 6.
    s = _FRACTION.sub(lambda m: (m.group(1) + "000000")[:7], s, count=1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def local_text_to_utc(text: str, fmt: str = "%Y-%m-%d %H:%M:%S", tz: timezone = IST) -> Optional[datetime]:
    """Local clock text (no zone written, e.g. setupapi.dev.log) -> UTC datetime.

    Default assumes the machine was set to India Standard Time.
    """
    if not text:
        return None
    try:
        naive = datetime.strptime(text.strip(), fmt)
    except ValueError:
        return None
    return naive.replace(tzinfo=tz).astimezone(UTC)


def iso_to_dt(iso: str) -> Optional[datetime]:
    """Read back a string made by to_iso()."""
    try:
        return datetime.strptime(iso, ISO_FORMAT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def iso_to_ist_text(iso: str) -> str:
    """'2026-10-22T04:30:00Z' -> '2026-10-22 10:00:00' (IST, for display only)."""
    dt = iso_to_dt(iso)
    return dt.astimezone(IST).strftime(IST_FORMAT) if dt else ""
