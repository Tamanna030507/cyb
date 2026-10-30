from __future__ import annotations
import math
import re
from collections import defaultdict
from typing import Any
import numpy as np

FEATURE_NAMES = [
    "proc_rate_5m",
    "file_write_rate_5m",
    "file_rename_rate_5m",
    "file_delete_rate_5m",
    "encrypt_ext_hits",
    "entropy_spike_count",
    "shadow_delete_hits",
    "lsass_hits",
    "log_clear_hits",
    "persistence_hits",
    "lateral_hits",
    "access_denied_rate_5m",
    "unique_dirs",
    "integrity_jump_hits",
    "network_exfil_bytes",
    "rare_proc_hits",
    "obfuscation_hits",
    "service_mod_hits"
]

RANSOM_EXT = {
    ".locked", ".encrypted", ".enc", ".crypt", ".ryuk", ".conti",
    ".lockbit", ".blackcat", ".wncry", ".maze", ".revil", ".hive"
}

SHADOW_RE = re.compile(r"vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete", re.I)
LSASS_RE = re.compile(r"lsass|procdump|mimikatz|sekurlsa|comsvcs", re.I)
LOGCLEAR_RE = re.compile(r"wevtutil\s+cl|Clear-EventLog", re.I)
PERSIST_RE = re.compile(r"schtasks\s+/create|reg\s+add.*\\Run|New-Service|wmic\s+process\s+call\s+create", re.I)
LATERAL_RE = re.compile(r"psexec|wmiexec|winrm|Enter-PSSession|\\\\[a-zA-Z0-9\-]+\\", re.I)
OBFUSC_RE = re.compile(r"-enc(odedcommand)?|IEX\s*\(|Invoke-Expression|DownloadString|FromBase64String", re.I)
RARE_PROCS = {"procdump.exe", "mimikatz.exe", "psexec.exe", "ransom.exe", "encryptor.exe"}

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())

def extract_features(events: list[dict[str, Any]], window_seconds: float = 300.0) -> np.ndarray:
    if not events:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float64)

    times = []
    for e in events:
        ts = e.get("timestamp", "")
        try:
            from datetime import datetime
            times.append(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
        except Exception:
            times.append(0.0)
    if not times:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    t_max = max(times)
    t_min = t_max - window_seconds

    proc_count = 0
    write_count = 0
    rename_count = 0
    delete_count = 0
    encrypt_hits = 0
    entropy_spikes = 0
    shadow_hits = 0
    lsass_hits = 0
    log_clear = 0
    persist = 0
    lateral = 0
    access_denied = 0
    dirs: set[str] = set()
    integrity = 0
    exfil_bytes = 0
    rare = 0
    obfusc = 0
    service_mod = 0

    for e, t in zip(events, times):
        if t < t_min:
            continue
        et = e.get("event_type", "")
        cmd = (e.get("command_line") or "") + " " + (e.get("process_name") or "")
        path = e.get("path") or e.get("new_path") or ""

        if et == "process_spawn":
            proc_count += 1
            if LSASS_RE.search(cmd):
                lsass_hits += 1
            if SHADOW_RE.search(cmd):
                shadow_hits += 1
            if LOGCLEAR_RE.search(cmd):
                log_clear += 1
            if PERSIST_RE.search(cmd):
                persist += 1
            if LATERAL_RE.search(cmd):
                lateral += 1
            if OBFUSC_RE.search(cmd):
                obfusc += 1
            pname = (e.get("process_name") or "").lower()
            if pname in RARE_PROCS:
                rare += 1
            if "sc.exe" in cmd.lower() or "New-Service" in cmd:
                service_mod += 1
            if "integrity" in cmd.lower() or "token" in cmd.lower():
                integrity += 1
        elif et in ("file_write", "file_create"):
            write_count += 1
            if any(path.lower().endswith(ext) for ext in RANSOM_EXT):
                encrypt_hits += 1
            content = e.get("content_sample") or ""
            if _entropy(content) > 7.0:
                entropy_spikes += 1
            if path:
                dirs.add("\\".join(path.split("\\")[:3]))
        elif et in ("file_rename", "file_move"):
            rename_count += 1
            newp = e.get("new_path") or ""
            if any(newp.lower().endswith(ext) for ext in RANSOM_EXT):
                encrypt_hits += 1
        elif et == "file_delete":
            delete_count += 1
        elif et == "access_denied":
            access_denied += 1
        elif et == "network_flow":
            exfil_bytes += int(e.get("bytes_sent") or 0)
        elif et == "token_elevation":
            integrity += 1

    window_min = max(window_seconds / 60.0, 0.1)
    vec = np.array([
        proc_count / window_min,
        write_count / window_min,
        rename_count / window_min,
        delete_count / window_min,
        float(encrypt_hits),
        float(entropy_spikes),
        float(shadow_hits),
        float(lsass_hits),
        float(log_clear),
        float(persist),
        float(lateral),
        access_denied / window_min,
        float(len(dirs)),
        float(integrity),
        float(exfil_bytes) / 1e6,
        float(rare),
        float(obfusc),
        float(service_mod)
    ], dtype=np.float64)
    return vec

def extract_batch(host_events: dict[str, list[dict]]) -> tuple[np.ndarray, list[str], list[int]]:
    X = []
    hosts = []
    labels = []
    for host, evs in host_events.items():
        X.append(extract_features(evs))
        hosts.append(host)
        labels.append(1 if any(e.get("label") == 1 for e in evs) else 0)
    return np.vstack(X) if X else np.zeros((0, len(FEATURE_NAMES))), hosts, labels