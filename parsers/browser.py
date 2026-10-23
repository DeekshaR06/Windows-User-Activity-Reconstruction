"""Microsoft Edge History parser (Member 4).

Reads an exported SQLite History database read-only from evidence_dir/Browser.
Creates URL_VISITED events from visits and FILE_DOWNLOADED events from downloads.
"""
from __future__ import annotations
import logging
import os
import sqlite3
from typing import List

from core.schema import Event
from core import timeutil

log = logging.getLogger(__name__)
SOURCE = "Browser"
FOLDER = "Browser"

def _tables(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

def _columns(conn, table):
    # table is selected only from a fixed list of known schema names.
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

def _get(row, *names, default=None):
    for name in names:
        try:
            value = row[name]
            if value is not None:
                return value
        except (KeyError, IndexError):
            pass
    return default

def _add(events, timestamp, meaning, event_type, summary, details, evidence_file):
    iso = timeutil.to_iso(timestamp)
    if not iso:
        return
    events.append(Event(timestamp_utc=iso, time_meaning=meaning, source=SOURCE,
                        event_type=event_type, user="", summary=summary,
                        details=details, evidence_file=evidence_file))

def _parse_history(path: str, evidence_dir: str) -> List[Event]:
    events: List[Event] = []
    relpath = os.path.relpath(path, evidence_dir).replace("\\", "/")
    uri = "file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        tables = _tables(conn)

        if "urls" in tables and "visits" in tables:
            url_cols = _columns(conn, "urls")
            visit_cols = _columns(conn, "visits")
            required = {"id", "url"}
            if required.issubset(url_cols) and {"url", "visit_time"}.issubset(visit_cols):
                title_expr = "u.title" if "title" in url_cols else "''"
                visit_id_expr = "v.id" if "id" in visit_cols else "NULL"
                sql = f"""SELECT v.visit_time, v.url AS url_id, {visit_id_expr} AS visit_id,
                          u.url AS url, {title_expr} AS title
                          FROM visits v JOIN urls u ON u.id = v.url
                          ORDER BY v.visit_time"""
                for row in conn.execute(sql):
                    dt = timeutil.webkit_to_utc(int(row["visit_time"] or 0))
                    if not dt or not row["url"]:
                        continue
                    title = row["title"] or ""
                    summary = f"Visited {row['url']}" + (f" — {title}" if title else "")
                    _add(events, dt, "visit_time", "URL_VISITED", summary,
                         {"url": row["url"], "title": title, "visit_id": row["visit_id"]},
                         relpath)
            else:
                log.warning("Browser: unexpected urls/visits schema in %s", path)

        if "downloads" in tables:
            cols = _columns(conn, "downloads")
            start_col = "start_time" if "start_time" in cols else ("start_time" if "start_time" in cols else None)
            target_col = "target_path" if "target_path" in cols else None
            url_col = "tab_url" if "tab_url" in cols else None
            source_col = "site_url" if "site_url" in cols else None
            select_cols = [c for c in ("id", "guid", "current_path", "target_path", "tab_url",
                                        "site_url", "start_time", "end_time", "received_bytes",
                                        "total_bytes", "state", "mime_type") if c in cols]
            if start_col and select_cols:
                sql = "SELECT " + ", ".join(select_cols) + " FROM downloads ORDER BY start_time"
                for row in conn.execute(sql):
                    dt = timeutil.webkit_to_utc(int(row["start_time"] or 0))
                    if not dt:
                        continue
                    target = _get(row, "target_path", "current_path", default="") or ""
                    tab_url = _get(row, "tab_url", default="") or ""
                    site_url = _get(row, "site_url", default="") or ""
                    filename = os.path.basename(str(target)) if target else "download"
                    details = {key: row[key] for key in row.keys()}
                    _add(events, dt, "download_start_time", "FILE_DOWNLOADED",
                         f"Downloaded {filename}" + (f" from {site_url or tab_url}" if (site_url or tab_url) else ""),
                         details, relpath)
        if not tables.intersection({"urls", "visits", "downloads"}):
            log.warning("Browser: no expected History tables in %s", path)
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        log.warning("Browser: could not parse History database %s: %s", path, exc)
    finally:
        if conn is not None:
            conn.close()
    return events

def parse(evidence_dir: str) -> List[Event]:
    folder = os.path.join(evidence_dir, FOLDER)
    if not os.path.isdir(folder):
        log.warning("%s: folder not found: %s", SOURCE, folder)
        return []
    events: List[Event] = []
    # The project layout specifies an exported Edge file named "History".
    for root, _, files in os.walk(folder):
        for name in files:
            if name.lower() == "history" or name.lower() == "history.db":
                events.extend(_parse_history(os.path.join(root, name), evidence_dir))
    return sorted(events, key=lambda event: event.timestamp_utc)
