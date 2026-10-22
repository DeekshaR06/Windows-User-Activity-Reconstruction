# Windows User Activity Reconstruction

Reads the traces Windows keeps about what a user did (programs run, files opened,
USB drives, web history, deleted files, logons), puts them on **one UTC timeline**,
flags suspicious patterns, and helps write a forensic report.
Course project: Digital Forensics. Team of 5, 10 days.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt                    # use Python 3.10 or 3.11

python main.py --demo --out output                 # works today, uses fake demo events
python main.py --evidence evidence/export --out output   # real evidence (after Day 2)
python -m unittest discover -s tests -t .          # run all tests
```

Outputs: `output/timeline.csv` (open in Excel), `output/timeline.db` (SQLite).

## How it fits together

```
evidence/export/  ->  parsers/*.py  ->  core/timeline.py  ->  output/timeline.csv + .db
 (exported files)     (1 per artifact)   (validate, dedupe,      -> analysis/ (sessions, rules)
                                          sort by time)          -> report/ (HTML timeline)
```

## The parser contract (read this if you write a parser)

Every file in `parsers/` has exactly one public function:

```python
def parse(evidence_dir: str) -> list[Event]: ...
```

* Build `Event` objects from `core/schema.py`. Do not invent new fields or event types
  (ask Member 5 first).
* **All times come from `core/timeutil.py`.** Never write your own conversion. The
  tool stores UTC only; IST is added for display in the CSV.
* Never crash on a bad file: `log.warning(...)` and continue.
* Fill `evidence_file` so every event can be traced back to its source file.
* Add one small test in `tests/`.

`python main.py` calls all six parsers; one that fails or is not written yet is skipped.

## Exported evidence folder layout (`evidence/export/`)

Whoever exports the evidence from FTK Imager must use exactly these folder names:

| Folder | What goes in it | Parser |
|---|---|---|
| `Prefetch/` | all `*.pf` from `C:\Windows\Prefetch` | prefetch.py |
| `Recent/` | all `*.lnk` from the user's `...\Windows\Recent` | lnk.py |
| `Logs/` | `Security.evtx`, `System.evtx`, `Application.evtx` | evtx.py |
| `RecycleBin/` | `$I*` and `$R*` files from the user's SID folder in `$Recycle.Bin` | recyclebin.py |
| `Registry/` | `SYSTEM`, `SOFTWARE` (+ their `.LOG1` / `.LOG2`) and `setupapi.dev.log` | usb.py |
| `Browser/` | the Edge `History` file | browser.py |

## Event types (fixed list)

`USER_LOGON, USER_LOGOFF, ACCOUNT_CREATED, SYSTEM_START, SYSTEM_SHUTDOWN, LOG_CLEARED,
PROGRAM_EXECUTED, FILE_OPENED, FILE_DELETED, USB_CONNECTED, USB_REMOVED, URL_VISITED, FILE_DOWNLOADED`

## Git rules

One branch per person, push at least once a day, merge only working code to `main`.
Never commit anything from `evidence/` (it is git-ignored on purpose).

## Layout

```
main.py            run the whole pipeline
core/              schema.py, timeutil.py, timeline.py   (Member 5)
parsers/           prefetch.py lnk.py (M2) | evtx.py recyclebin.py (M3) | usb.py browser.py (M4)
analysis/          sessions.py, rules.py  (Member 5, Days 6-7)
report/            html_timeline.py       (Member 5, Days 8-9)
validation/        ground_truth + detection table templates (Member 1)
demo/              fake_events.csv for building and practising before real evidence exists
tests/             unit tests
evidence/          NOT in Git: image, export/, hashes.txt
```
