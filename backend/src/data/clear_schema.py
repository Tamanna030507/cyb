from __future__ import annotations
import csv
import json
import random
from pathlib import Path
from typing import Any
import numpy as np

KNOWN_FAMILIES = [
    "LockBit", "Conti", "Hive", "BlackCat", "Ryuk", "Maze", "REvil", "WannaCry"
]
UNKNOWN_FAMILIES = [
    "Play", "Royal", "BlackBasta", "Clop", "Akira"
]

def generate_clear_mini(
    out_dir: str | Path,
    n_benign: int = 5000,
    n_known: int = 2200,
    n_unknown: int = 1800,
    seed: int = 42
) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    rnd = random.Random(seed)
    rows: list[dict[str, Any]] = []
    t = 0.0
    workload_id = 0

    def emit(label: int, family: str, variant_split: str, pid: int, path: str, opcode: int, size: int, war: int, dt: float | None = None):
        nonlocal t
        t += float(dt if dt is not None else rng.uniform(0.001, 0.05))
        rows.append({
            "timestamp": round(t, 6),
            "opcode": opcode,
            "offset": int(rng.integers(0, 10_000_000)),
            "size": size,
            "label": label,
            "war": war,
            "process_name": path.split("\\")[-1] if "\\" in path else "proc.exe",
            "pid": pid,
            "path": path,
            "family": family,
            "variant_split": variant_split,
            "workload_id": workload_id
        })

    for i in range(n_benign):
        workload_id = i // 80
        pid = 1000 + (i % 40)
        opcode = 2 if rng.random() < 0.6 else 1
        size = int(rng.choice([4096, 8192, 16384, 32768, 65536]))
        path = f"C:\\Users\\user\\Documents\\file_{i % 300}.docx"
        war = int(rng.integers(0, 2))
        emit(0, "benign", "benign", pid, path, opcode, size, war, dt=float(rng.uniform(0.01, 0.12)))

    for i in range(n_known):
        workload_id = 1000 + i // 55
        fam = rnd.choice(KNOWN_FAMILIES)
        pid = 5000 + (i % 14)
        style = rnd.random()
        if style < 0.55:
            opcode = 1
            size = int(rng.choice([65536, 131072, 262144, 524288]))
            war = int(rng.integers(4, 30))
            path = f"C:\\Users\\victim\\data\\doc_{i}{rnd.choice(['.locked', '.ryuk', '.conti', '.encrypted'])}"
            dt = float(rng.uniform(0.001, 0.02))
        elif style < 0.8:
            opcode = 1
            size = int(rng.choice([32768, 65536]))
            war = int(rng.integers(1, 8))
            path = f"C:\\Users\\victim\\data\\doc_{i}.docx"
            dt = float(rng.uniform(0.005, 0.04))
        else:
            opcode = 2
            size = int(rng.choice([4096, 8192, 16384]))
            war = 0
            path = f"C:\\Users\\victim\\data\\doc_{i}.docx"
            dt = float(rng.uniform(0.01, 0.08))
        emit(1, fam, "known", pid, path, opcode, size, war, dt=dt)

    for i in range(n_unknown):
        workload_id = 2000 + i // 45
        fam = rnd.choice(UNKNOWN_FAMILIES)
        pid = 8000 + (i % 16)
        style = rnd.random()
        if style < 0.25:
            opcode = 1
            size = int(rng.choice([8192, 16384, 32768]))
            war = int(rng.integers(0, 3))
            path = f"C:\\Users\\victim\\share\\report_{i}.docx"
            dt = float(rng.uniform(0.05, 0.25))
        elif style < 0.5:
            opcode = 1
            size = int(rng.choice([4096, 8192, 16384]))
            war = int(rng.integers(0, 2))
            path = f"C:\\Windows\\Temp\\tmp_{i}.dat"
            dt = float(rng.uniform(0.08, 0.3))
        elif style < 0.75:
            opcode = 2
            size = int(rng.choice([4096, 8192, 65536]))
            war = 0
            path = f"C:\\Users\\victim\\share\\file_{i}.docx"
            dt = float(rng.uniform(0.04, 0.2))
        else:
            opcode = 1
            size = int(rng.choice([16384, 32768, 65536]))
            war = int(rng.integers(1, 6))
            path = f"C:\\Users\\victim\\share\\file_{i}{rnd.choice(['.dat', '.bin', '.tmp'])}"
            dt = float(rng.uniform(0.03, 0.15))
        emit(1, fam, "unknown", pid, path, opcode, size, war, dt=dt)

    for i in range(800):
        workload_id = 3000 + i // 40
        pid = 1000 + (i % 40)
        opcode = 1 if rng.random() < 0.45 else 2
        size = int(rng.choice([65536, 131072]))
        path = f"C:\\Users\\user\\Downloads\\batch_{i}.zip"
        war = int(rng.integers(0, 4))
        emit(0, "benign", "benign", pid, path, opcode, size, war, dt=float(rng.uniform(0.002, 0.03)))

    path_csv = out / "clear_mini.csv"
    fields = ["timestamp", "opcode", "offset", "size", "label", "war", "process_name", "pid", "path", "family", "variant_split", "workload_id"]
    with path_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    meta = {
        "source": "CLEAR-schema hard mini sample",
        "design": "Unknown variants are low-and-slow, low-WAR, normal extensions, mixed with benign-like I/O so recall is non-trivial",
        "n_rows": len(rows),
        "known_families": KNOWN_FAMILIES,
        "unknown_families": UNKNOWN_FAMILIES,
        "kaggle_full": "https://www.kaggle.com/datasets/johndoenvme/clear-command-level-annotated-ransomware",
        "paper": "CLEAR: Command Level Annotated Dataset for Ransomware Detection (NeurIPS 2025)"
    }
    (out / "clear_mini_card.json").write_text(json.dumps(meta, indent=2))
    return path_csv

def load_clear_csv(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    with Path(path).open() as f:
        for r in csv.DictReader(f):
            rows.append({
                "timestamp": float(r["timestamp"]),
                "opcode": int(r["opcode"]),
                "offset": int(r["offset"]),
                "size": int(r["size"]),
                "label": int(r["label"]),
                "war": int(float(r.get("war") or 0)),
                "process_name": r.get("process_name") or "",
                "pid": int(float(r.get("pid") or 0)),
                "path": r.get("path") or "",
                "family": r.get("family") or "",
                "variant_split": r.get("variant_split") or "",
                "workload_id": int(float(r.get("workload_id") or 0))
            })
    return rows
