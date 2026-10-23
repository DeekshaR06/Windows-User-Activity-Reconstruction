"""analysis/evidence_check.py -- is evidence/export/ laid out the way the parsers expect? (owner: Member 5)

Run it any time:   py -3.11 -m analysis.evidence_check evidence/export
main.py also prints this report before every real run.

It only LOOKS at folder and file names. It never opens or changes the evidence.
"""
from __future__ import annotations

import fnmatch
import os
import sys
from typing import Dict, List

# (folder, file pattern, what to export, owner).  Patterns are not case sensitive.
EXPECTED = [
    ("Prefetch",   "*.pf",    "all .pf files from C:\\Windows\\Prefetch",                         "Member 2"),
    ("Recent",     "*.lnk",   "all .lnk files from the user's ...\\Windows\\Recent folder",       "Member 2"),
    ("Logs",       "*.evtx",  "Security.evtx, System.evtx, Application.evtx",                     "Member 3"),
    ("RecycleBin", "$i*",     "the $I... and $R... files from the user's SID folder",             "Member 3"),
    ("Registry",   "system",  "the SYSTEM hive (+ .LOG1/.LOG2) and setupapi.dev.log",             "Member 4"),
    ("Browser",    "history", "the Edge 'History' file",                                          "Member 4"),
]


def _count(folder: str, pattern: str) -> int:
    n = 0
    for _root, _dirs, files in os.walk(folder):
        n += sum(1 for f in files if fnmatch.fnmatch(f.lower(), pattern))
    return n


def check(evidence_dir: str) -> List[Dict]:
    """One result per expected folder: status is 'ok', 'empty' (folder but no matching files) or 'missing'."""
    results = []
    for folder, pattern, what, owner in EXPECTED:
        path = os.path.join(evidence_dir, folder)
        # folder names are matched without regard to upper/lower case (Windows does the same)
        real = None
        if os.path.isdir(evidence_dir):
            real = next((d for d in os.listdir(evidence_dir)
                         if d.lower() == folder.lower() and os.path.isdir(os.path.join(evidence_dir, d))), None)
        if real is None:
            status, count = "missing", 0
        else:
            count = _count(os.path.join(evidence_dir, real), pattern)
            status = "ok" if count else "empty"
        extra = ""
        if folder == "Registry" and real is not None:
            has_log = _count(os.path.join(evidence_dir, real), "setupapi.dev.log") > 0
            if not has_log:
                extra = "setupapi.dev.log not found (USB times from the log will be missing)"
        results.append({"folder": folder, "path": path, "status": status, "count": count,
                        "what": what, "owner": owner, "extra": extra})
    return results


def report_lines(results: List[Dict]) -> List[str]:
    lines = []
    for r in results:
        if r["status"] == "ok":
            line = "  [ok]      %-11s %d matching file(s)" % (r["folder"] + "/", r["count"])
        elif r["status"] == "empty":
            line = "  [EMPTY]   %-11s folder exists but has no matching files. Expected: %s (%s)" % (
                r["folder"] + "/", r["what"], r["owner"])
        else:
            line = "  [MISSING] %-11s folder not found. Expected: %s (%s)" % (
                r["folder"] + "/", r["what"], r["owner"])
        lines.append(line)
        if r["extra"]:
            lines.append("            note: " + r["extra"])
    return lines


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    folder = args[0] if args else os.path.join("evidence", "export")
    if not os.path.isdir(folder):
        print("folder not found: %s" % folder, file=sys.stderr)
        return 2
    results = check(folder)
    print("Evidence folder check: %s" % folder)
    print("\n".join(report_lines(results)))
    return 0 if all(r["status"] == "ok" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
