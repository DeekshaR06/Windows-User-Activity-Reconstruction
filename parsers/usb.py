"""USB artifact parser (Member 4).

Reads exported Registry/SYSTEM, Registry/SOFTWARE, and Registry/setupapi.dev.log.
Registry enumeration proves a device was recorded by Windows; its key LastWrite
time is NOT necessarily the exact plug-in time. setupapi.dev.log section-start
times are installation/configuration times, not guaranteed connection times.
"""
from __future__ import annotations
import logging
import os
import re
from typing import Dict, List, Optional

from core.schema import Event
from core import timeutil

log = logging.getLogger(__name__)
SOURCE = "USB"
FOLDER = "Registry"
USB_ID = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:\\([^\\]+))?", re.I)


def _event(timestamp, meaning: str, summary: str, details: Dict, evidence_file: str) -> Optional[Event]:
    if timestamp is not None and getattr(timestamp, "tzinfo", None) is None:
        timestamp = timestamp.replace(tzinfo=timeutil.UTC)
    iso = timeutil.to_iso(timestamp)
    if not iso:
        return None
    return Event(timestamp_utc=iso, time_meaning=meaning, source=SOURCE,
                 event_type="USB_CONNECTED", user="", summary=summary,
                 details=details, evidence_file=evidence_file)


def _canonical_setupapi_dev(dev_id: str) -> tuple[str, str, dict]:
    """Return (canonical_id, readable_label, extra_details)."""
    cleaned = dev_id.strip()
    cleaned = re.sub(r"^(?:STORAGE\\Volume\\_\?\?_|SWD\\WPDBUSENUM\\_\?\?_)", "", cleaned, flags=re.I)
    cleaned = cleaned.rstrip("}")

    # Check for USBSTOR disk pattern: USBSTOR#Disk&Ven_VendorCo&Prod_ProductCode&Rev_2.00#6255861094384049347&0#{...
    m_disk = re.search(r"USBSTOR#Disk&Ven_([^&]+)&Prod_([^&]+)&Rev_([^#]+)#([^#&]+)", cleaned, re.I)
    if m_disk:
        ven, prod, rev, serial = m_disk.group(1), m_disk.group(2), m_disk.group(3), m_disk.group(4)
        label = f"{ven} {prod} (serial {serial})"
        return (f"USBSTOR_{ven}_{prod}_{serial}".upper(), label,
                {"vendor": ven, "product": prod, "revision": rev, "serial": serial, "raw_id": dev_id})

    # Check for USB\VID_xxxx&PID_xxxx...
    m_vid = re.search(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:[\\&]([^\s,';\"\}\]]+))?", cleaned, re.I)
    if m_vid:
        vid, pid, rest = m_vid.group(1), m_vid.group(2), m_vid.group(3) or ""
        label = f"VID_{vid}&PID_{pid}" + (f" ({rest})" if rest else "")
        return (f"USB_VID_{vid}_PID_{pid}_{rest}".upper(), label,
                {"vendor_id": vid, "product_id": pid, "serial_or_instance": rest, "raw_id": dev_id})

    return (cleaned.upper(), cleaned, {"raw_id": dev_id})


def _parse_setupapi(path: str, evidence_dir: str) -> List[Event]:
    events: List[Event] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        log.warning("USB: could not read %s: %s", path, exc)
        return events

    relpath = os.path.relpath(path, evidence_dir).replace("\\", "/")
    current_time = None
    section_name = ""
    section_devices = set()
    seen_events = set()

    def flush_section():
        nonlocal current_time, section_name, section_devices
        if current_time and section_devices:
            canonical_seen = set()
            for dev_str in sorted(section_devices):
                canon_key, label, meta = _canonical_setupapi_dev(dev_str)
                if canon_key in canonical_seen:
                    continue
                canonical_seen.add(canon_key)

                dedup_key = (str(current_time), canon_key)
                if dedup_key in seen_events:
                    continue
                seen_events.add(dedup_key)

                summary = f"Windows recorded USB device installation/configuration: {label}"
                details = {
                    "device": label,
                    "section": section_name,
                    "timestamp_caveat": "Installation/configuration time; not guaranteed to be physical plug-in time."
                }
                details.update(meta)
                ev = _event(current_time, "setupapi_install_section_start", summary, details, relpath)
                if ev:
                    events.append(ev)
        section_devices.clear()

    for line in lines:
        stripped = line.strip()

        # Section start timestamp
        m_time = re.search(r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", stripped, re.I)
        if m_time:
            current_time = timeutil.local_text_to_utc(m_time.group(1).split(".")[0], "%Y/%m/%d %H:%M:%S")

        # Section header: >>> [Device Install ...] or >>>  [Device Install ...]
        m_sec = re.search(r"^>>>\s+\[([^\]]+)\]", stripped)
        if m_sec:
            if section_devices and current_time:
                flush_section()
            section_name = m_sec.group(1).strip()
            if "-" in section_name:
                part = section_name.split("-", 1)[1].strip()
                if re.search(r"(?:USB\\VID_|USBSTOR[#\\])", part, re.I):
                    section_devices.add(part)

        # Section end
        if re.search(r"^<<<\s+(?:Section end|\[Exit status)", stripped, re.I):
            flush_section()
            current_time = None
            section_name = ""
            continue

        # Check for device patterns inside the section
        m_vid = re.search(r"(USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}(?:&[^\\\s,';\"\}\]]+)?(?:\\[^\s,';\"\}\]]+)?)", stripped, re.I)
        if m_vid:
            section_devices.add(m_vid.group(1))

        m_stor = re.search(r"((?:SWD\\WPDBUSENUM\\_\?\?_)?USBSTOR[#\\][^\s,';\"\}\]]+)", stripped, re.I)
        if m_stor:
            section_devices.add(m_stor.group(1))

    flush_section()
    return events


def _get_mounted_devices(reg) -> Dict[str, str]:
    """Map device signature / serial to drive letter from SYSTEM MountedDevices."""
    drive_map: Dict[str, str] = {}
    try:
        md = reg.root().subkey("MountedDevices")
        for val in md.values():
            val_name = val.name()
            if val_name.startswith("\\DosDevices\\"):
                drive = val_name.replace("\\DosDevices\\", "")
                data = bytes(val.value()).decode("utf-16le", errors="ignore")
                drive_map[data] = drive
    except Exception:
        pass
    return drive_map


def _parse_system_hive(path: str, evidence_dir: str) -> List[Event]:
    events: List[Event] = []
    try:
        from Registry import Registry
    except ImportError:
        log.warning("USB: python-registry is not installed; skipping SYSTEM hive")
        return events

    relpath = os.path.relpath(path, evidence_dir).replace("\\", "/")
    try:
        reg = Registry.Registry(path)
        root = reg.root()
        drive_map = _get_mounted_devices(reg)

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
            try:
                cs_key = root.subkey(cs)
                enum_key = cs_key.subkey("Enum")
            except Exception:
                continue

            for branch_name in ("USBSTOR", "USB"):
                try:
                    branch = enum_key.subkey(branch_name)
                except Exception:
                    continue

                for device in branch.subkeys():
                    vidpid = device.name()
                    for instance in device.subkeys():
                        try:
                            lastwrite = instance.timestamp()
                            if lastwrite is not None and lastwrite.tzinfo is None:
                                lastwrite = lastwrite.replace(tzinfo=timeutil.UTC)
                            serial = instance.name()
                            props: Dict[str, str] = {}
                            for val in instance.values():
                                try:
                                    if val.name() in ("FriendlyName", "DeviceDesc", "Mfg", "HardwareID", "Service"):
                                        props[val.name()] = str(val.value())
                                except Exception:
                                    pass

                            if vidpid.upper().startswith("ROOT_HUB"):
                                continue

                            key = (cs, branch_name, vidpid, serial, str(lastwrite))
                            if key in seen:
                                continue
                            seen.add(key)

                            friendly = props.get("FriendlyName") or vidpid
                            summary = f"USB device recorded in Registry: {friendly} ({serial})"
                            details = {
                                "control_set": cs,
                                "registry_path": f"{cs}\\Enum\\{branch_name}\\{vidpid}\\{serial}",
                                "device_key": vidpid,
                                "instance_or_serial": serial,
                                "properties": props,
                                "timestamp_caveat": "Registry key LastWrite is not necessarily the exact connection time."
                            }
                            for map_key, letter in drive_map.items():
                                if serial in map_key or vidpid in map_key:
                                    details["drive_letter"] = letter
                                    summary += f" [Drive {letter}]"
                                    break

                            ev = _event(lastwrite, "registry_key_last_write", summary, details, relpath)
                            if ev:
                                events.append(ev)
                        except Exception as exc:
                            log.warning("USB: failed reading a device instance under %s: %s", branch_name, exc)
    except Exception as exc:
        log.warning("USB: could not parse SYSTEM hive %s: %s", path, exc)
    return events


def _parse_software_hive(path: str, evidence_dir: str) -> List[Event]:
    events: List[Event] = []
    try:
        from Registry import Registry
    except ImportError:
        return events

    relpath = os.path.relpath(path, evidence_dir).replace("\\", "/")
    try:
        reg = Registry.Registry(path)
        root = reg.root()
        wpd = root.subkey("Microsoft").subkey("Windows Portable Devices").subkey("Devices")
        for dev in wpd.subkeys():
            dev_name = dev.name()
            if "USBSTOR" not in dev_name.upper():
                continue
            lastwrite = dev.timestamp()
            if lastwrite is not None and lastwrite.tzinfo is None:
                lastwrite = lastwrite.replace(tzinfo=timeutil.UTC)
            friendly = ""
            for val in dev.values():
                if val.name() == "FriendlyName":
                    friendly = str(val.value())
            summary = f"USB storage device volume recorded in Registry: {friendly or dev_name}"
            details = {
                "registry_path": f"Microsoft\\Windows Portable Devices\\Devices\\{dev_name}",
                "device_id": dev_name,
                "friendly_name": friendly,
                "timestamp_caveat": "Registry key LastWrite reflects device mount or volume name update."
            }
            ev = _event(lastwrite, "portable_device_last_write", summary, details, relpath)
            if ev:
                events.append(ev)
    except Exception:
        pass
    return events


def parse(evidence_dir: str) -> List[Event]:
    folder = os.path.join(evidence_dir, FOLDER)
    if not os.path.isdir(folder):
        log.warning("%s: folder not found: %s", SOURCE, folder)
        return []
    events: List[Event] = []
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        uname = name.upper()
        if uname in ("SYSTEM", "SYSTEM.HIVE"):
            events.extend(_parse_system_hive(path, evidence_dir))
        elif uname in ("SOFTWARE", "SOFTWARE.HIVE"):
            events.extend(_parse_software_hive(path, evidence_dir))
        elif name.lower() == "setupapi.dev.log":
            events.extend(_parse_setupapi(path, evidence_dir))
    return sorted(events, key=lambda event: event.timestamp_utc)
