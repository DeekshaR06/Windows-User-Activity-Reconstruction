"""USB artifact parser (Member 4).

Reads exported Registry/SYSTEM and Registry/setupapi.dev.log.
Registry enumeration proves a device was recorded by Windows; its key LastWrite
time is NOT necessarily the exact plug-in time. setupapi.dev.log section-start
times are installation/configuration times, not guaranteed connection times.
"""
from __future__ import annotations
import logging
import os
import re
from typing import List

from core.schema import Event
from core import timeutil

log = logging.getLogger(__name__)
SOURCE = "USB"
FOLDER = "Registry"
USB_ID = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:\\([^\\]*)|\\([^\\]+)", re.I)

def _event(timestamp, meaning, summary, details, evidence_file):
    iso = timeutil.to_iso(timestamp)
    if not iso:
        return None
    return Event(timestamp_utc=iso, time_meaning=meaning, source=SOURCE,
                 event_type="USB_CONNECTED", user="", summary=summary,
                 details=details, evidence_file=evidence_file)

def _parse_setupapi(path: str, evidence_dir: str) -> List[Event]:
    events = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        log.warning("USB: could not read %s: %s", path, exc)
        return events

    current_time = None
    section = ""
    for line in lines:
        # Typical line: >>>  Section start 2026/10/22 10:15:00.000
        m = re.search(r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", line, re.I)
        if m:
            current_time = timeutil.local_text_to_utc(m.group(1).split(".")[0],
                                                       "%Y/%m/%d %H:%M:%S")
            section = ""
            continue
        if line.startswith(">>> ["):
            section = line.strip()
        if current_time and re.search(r"USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}", line, re.I):
            match = re.search(r"(USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}(?:&[^\\\s]+)?(?:\\[^\s]+)?)", line, re.I)
            device_id = match.group(1) if match else line.strip()
            ev = _event(current_time, "setupapi_install_section_start",
                        f"Windows recorded USB device installation/configuration: {device_id}",
                        {"device_id": device_id, "section": section,
                         "timestamp_caveat": "Installation/configuration time; not guaranteed to be physical plug-in time."},
                        os.path.relpath(path, evidence_dir).replace("\\", "/"))
            if ev:
                events.append(ev)
    return events

def _parse_system_hive(path: str, evidence_dir: str) -> List[Event]:
    events = []
    try:
        from Registry import Registry
    except ImportError:
        log.warning("USB: python-registry is not installed; skipping SYSTEM hive")
        return events
    try:
        reg = Registry.Registry(path)
        root = reg.root()
        # Resolve active control set where possible, then also inspect numbered control sets.
        control_sets = []
        try:
            select = reg.open("Select")
            current = int(select.value("Current").value())
            control_sets.append(f"ControlSet{current:03d}")
        except Exception:
            pass
        try:
            for key in root.subkeys():
                if re.fullmatch(r"ControlSet\d{3}", key.name(), re.I) and key.name() not in control_sets:
                    control_sets.append(key.name())
        except Exception:
            pass
        seen = set()
        for cs in control_sets:
            for branch in (f"{cs}\\Enum\\USBSTOR", f"{cs}\\Enum\\USB"):
                try:
                    parent = reg.open(branch)
                except Exception:
                    continue
                try:
                    for device in parent.subkeys():
                        for instance in device.subkeys():
                            try:
                                lastwrite = instance.timestamp()
                                vidpid = device.name()
                                serial = instance.name()
                                props = {}
                                for val in instance.values():
                                    try:
                                        if val.name() in ("FriendlyName", "DeviceDesc", "Mfg", "HardwareID", "Service"):
                                            props[val.name()] = val.value()
                                    except Exception:
                                        pass
                                key = (cs, branch, vidpid, serial, str(lastwrite))
                                if key in seen:
                                    continue
                                seen.add(key)
                                ev = _event(lastwrite, "registry_key_last_write",
                                    f"USB device recorded in Registry: {vidpid} ({serial})",
                                    {"control_set": cs, "registry_path": f"{branch}\\{vidpid}\\{serial}",
                                     "device_key": vidpid, "instance_or_serial": serial,
                                     "properties": props,
                                     "timestamp_caveat": "Registry key LastWrite is not necessarily the exact connection time."},
                                    os.path.relpath(path, evidence_dir).replace("\\", "/"))
                                if ev:
                                    events.append(ev)
                            except Exception as exc:
                                log.warning("USB: failed reading a device instance under %s: %s", branch, exc)
                except Exception as exc:
                    log.warning("USB: failed reading %s: %s", branch, exc)
    except Exception as exc:
        log.warning("USB: could not parse SYSTEM hive %s: %s", path, exc)
    return events

def parse(evidence_dir: str) -> List[Event]:
    folder = os.path.join(evidence_dir, FOLDER)
    if not os.path.isdir(folder):
        log.warning("%s: folder not found: %s", SOURCE, folder)
        return []
    events: List[Event] = []
    # Export may name the hive SYSTEM or SYSTEM.hive.
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if os.path.isfile(path) and name.upper() in ("SYSTEM", "SYSTEM.HIVE"):
            events.extend(_parse_system_hive(path, evidence_dir))
        elif os.path.isfile(path) and name.lower() == "setupapi.dev.log":
            events.extend(_parse_setupapi(path, evidence_dir))
    # USB removal cannot be reliably inferred from these artifacts alone.
    return events
