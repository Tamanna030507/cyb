from __future__ import annotations
from collections import defaultdict
from typing import Any
import numpy as np

SEQ_FEATURE_NAMES = [
    "write_ratio",
    "rename_like_rate",
    "mean_write_size",
    "war_mean",
    "war_max",
    "cmd_rate",
    "unique_offsets",
    "size_entropy_proxy",
    "write_burst",
    "path_ext_hits"
]

def window_features(commands: list[dict[str, Any]], window: int = 50) -> np.ndarray:
    if not commands:
        return np.zeros(len(SEQ_FEATURE_NAMES), dtype=np.float64)
    chunk = commands[-window:]
    n = len(chunk)
    writes = [c for c in chunk if c.get("opcode") == 1]
    reads = [c for c in chunk if c.get("opcode") == 2]
    write_ratio = len(writes) / max(n, 1)
    rename_like = sum(1 for c in chunk if any(x in (c.get("path") or "").lower() for x in [".locked", ".encrypted", ".ryuk", ".conti"]))
    mean_write_size = float(np.mean([c["size"] for c in writes])) if writes else 0.0
    wars = [c.get("war", 0) for c in chunk]
    war_mean = float(np.mean(wars)) if wars else 0.0
    war_max = float(np.max(wars)) if wars else 0.0
    ts = [c["timestamp"] for c in chunk]
    duration = max(ts[-1] - ts[0], 1e-3)
    cmd_rate = n / duration
    unique_offsets = len({c["offset"] for c in chunk}) / max(n, 1)
    sizes = [c["size"] for c in chunk]
    size_entropy_proxy = float(np.std(sizes)) / (float(np.mean(sizes)) + 1e-6)
    write_burst = 0.0
    if len(writes) >= 2:
        wts = [c["timestamp"] for c in writes]
        gaps = np.diff(wts)
        write_burst = float(np.sum(gaps < 0.01) / max(len(gaps), 1))
    path_ext_hits = float(rename_like)
    return np.array([
        write_ratio,
        rename_like / max(n, 1),
        mean_write_size / 1e5,
        war_mean,
        war_max,
        cmd_rate,
        unique_offsets,
        size_entropy_proxy,
        write_burst,
        path_ext_hits / max(n, 1)
    ], dtype=np.float64)

def group_workloads(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    g: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        g[int(r["workload_id"])].append(r)
    for k in g:
        g[k].sort(key=lambda x: x["timestamp"])
    return dict(g)

def build_xy_from_clear(rows: list[dict[str, Any]], window: int = 50) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    workloads = group_workloads(rows)
    X = []
    y = []
    splits = []
    families = []
    for wid, cmds in workloads.items():
        X.append(window_features(cmds, window=window))
        lab = 1 if any(c["label"] == 1 for c in cmds) else 0
        y.append(lab)
        vs = next((c["variant_split"] for c in cmds if c.get("variant_split")), "benign")
        fam = next((c["family"] for c in cmds if c.get("family")), "benign")
        splits.append(vs)
        families.append(fam)
    return np.vstack(X), np.array(y), splits, families