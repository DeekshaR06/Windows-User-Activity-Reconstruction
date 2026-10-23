"""analysis/validate.py -- compare the timeline with the answer key (owner: Member 5, for Member 1).

For every step in ground_truth.csv it looks for a timeline event of the expected type and source
near the time we wrote down, and fills in the detection table:

    py -3.11 -m analysis.validate --truth validation/ground_truth.csv \
        --timeline output/timeline.csv --out validation/detection_table.csv

This gives a quick, repeatable cross-check.  It does not replace the human check: Member 1
still reads the rows and writes the plain-words explanation for every "No".

Rules of the match:
  * the event_type must be the expected one, and the source too (if the answer key names one)
  * the time must be within --window seconds (default 120) of the answer-key time
  * if several events fit, the closest one is reported and the others are counted in the notes
  * a step with no time in the answer key is skipped, not marked "No"
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

COLUMNS = ["step", "action", "expected_source", "expected_event_type", "found_yes_no",
           "time_in_timeline_ist", "time_difference_seconds", "notes"]
FMT = "%Y-%m-%d %H:%M:%S"
TIMEZONE_HINT_SECONDS = 19800          # 5 hours 30 minutes


def _read(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _parse(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime((text or "").strip(), FMT)
    except ValueError:
        return None


def compare(truth: List[Dict[str, str]], timeline: List[Dict[str, str]], window: int = 120) -> List[Dict[str, str]]:
    events = []
    for r in timeline:
        t = _parse(r.get("timestamp_ist", ""))
        if t:
            events.append((t, r))

    out = []
    for step in truth:
        row = {"step": step.get("step", ""), "action": step.get("action", ""),
               "expected_source": step.get("expected_source", ""),
               "expected_event_type": step.get("expected_event_type", ""),
               "found_yes_no": "", "time_in_timeline_ist": "", "time_difference_seconds": "", "notes": ""}
        t0 = _parse(step.get("time_ist", ""))
        if t0 is None:
            row["notes"] = "not checked: no valid time_ist in the answer key (format 2026-10-23 10:31:22)"
            out.append(row)
            continue

        same_kind = [(t, r) for t, r in events
                     if r.get("event_type") == row["expected_event_type"]
                     and (not row["expected_source"] or r.get("source") == row["expected_source"])]
        near = sorted(((t, r) for t, r in same_kind if abs((t - t0).total_seconds()) <= window),
                      key=lambda x: abs((x[0] - t0).total_seconds()))
        if near:
            t, r = near[0]
            row["found_yes_no"] = "Yes"
            row["time_in_timeline_ist"] = t.strftime(FMT)
            row["time_difference_seconds"] = str(int((t - t0).total_seconds()))
            more = ("; %d more matching event(s) within the window" % (len(near) - 1)) if len(near) > 1 else ""
            row["notes"] = ("matched: " + r.get("summary", "")[:80] + more).strip()
        else:
            row["found_yes_no"] = "No"
            if not same_kind:
                row["notes"] = "no %s event from %s anywhere in the timeline" % (
                    row["expected_event_type"], row["expected_source"] or "any source")
            else:
                t, r = min(same_kind, key=lambda x: abs((x[0] - t0).total_seconds()))
                gap = int(abs((t - t0).total_seconds()))
                hint = ""
                if abs(gap - TIMEZONE_HINT_SECONDS) <= window:
                    hint = " <- about 5h30m: possible UTC/IST time-zone mistake, tell Member 5"
                row["notes"] = "closest %s event is %d seconds away (%s)%s" % (
                    row["expected_event_type"], gap, t.strftime(FMT), hint)
        out.append(row)
    return out


def summary(rows: List[Dict[str, str]]) -> str:
    checked = [r for r in rows if r["found_yes_no"]]
    found = sum(1 for r in checked if r["found_yes_no"] == "Yes")
    skipped = len(rows) - len(checked)
    pct = (100.0 * found / len(checked)) if checked else 0.0
    text = "%d of %d checked steps found (%.0f%%)" % (found, len(checked), pct)
    return text + ("; %d skipped (no time)" % skipped if skipped else "")


def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Compare timeline.csv with the answer key (ground_truth.csv)")
    ap.add_argument("--truth", default=os.path.join("validation", "ground_truth.csv"))
    ap.add_argument("--timeline", default=os.path.join("output", "timeline.csv"))
    ap.add_argument("--out", default=os.path.join("validation", "detection_table.csv"))
    ap.add_argument("--window", type=int, default=120, help="allowed time difference in seconds (default 120)")
    args = ap.parse_args(argv)
    for p in (args.truth, args.timeline):
        if not os.path.exists(p):
            print("file not found: %s" % p, file=sys.stderr)
            return 2
    rows = compare(_read(args.truth), _read(args.timeline), args.window)
    write_csv(rows, args.out)
    for r in rows:
        print("%-5s %-4s %-26s %s" % (r["step"], r["found_yes_no"] or "-", r["expected_event_type"], r["notes"]))
    print("\n" + summary(rows))
    print("-> " + args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
