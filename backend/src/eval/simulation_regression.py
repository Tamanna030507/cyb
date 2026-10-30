from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import numpy as np

from data.generator import EventGenerator
from features.extract import extract_features
from models.train import DetectionModel
from eval.evaluate import load_events, group_by_host, time_based_split

SIM_TAG = "SIMULATION"

def generate_simulation_batch(seed: int = 99) -> list[dict[str, Any]]:
    gen = EventGenerator(seed=seed)
    from datetime import datetime, timedelta
    start = datetime(2025, 7, 1, 8, 0, 0)
    events = gen.attack_sequence("sim-host-01", "sim-user", start, style="standard")
    for e in events:
        e["tag"] = SIM_TAG
        e["label"] = 1
    return events

def run_simulation_regression(model_path: Path, data_path: Path, out_path: Path) -> dict[str, Any]:
    events = load_events(data_path)
    real_events = [e for e in events if e.get("tag") != SIM_TAG]
    host_events = group_by_host(real_events)
    train_h, test_h = time_based_split(host_events)

    X_train, y_train = [], []
    for h, evs in train_h.items():
        X_train.append(extract_features(evs))
        y_train.append(1 if any(e.get("label") == 1 for e in evs) else 0)
    X_train = np.vstack(X_train)
    y_train = np.array(y_train)

    model = DetectionModel()
    if model_path.exists():
        model.load(model_path)
    else:
        model.fit(X_train, y_train)
        model.save(model_path)

    sim = generate_simulation_batch()
    sim_vec = extract_features(sim).reshape(1, -1)
    before = float(model.score(sim_vec)[0])

    y_poison = y_train.copy()
    pos = np.where(y_train == 1)[0]
    if len(pos):
        y_poison[pos[: max(1, len(pos) // 5)]] = 0
    model.fit(X_train, y_poison)
    after = float(model.score(sim_vec)[0])

    result = {
        "simulation_tag": SIM_TAG,
        "sim_events_count": len(sim),
        "score_before_retrain": round(before, 4),
        "score_after_poisoned_retrain": round(after, 4),
        "regression_detected": after < before - 0.05,
        "policy": "SIMULATION events are scored for regression only and never enter training labels"
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(run_simulation_regression(
        root / "models" / "detector.joblib",
        root / "data" / "synthetic" / "events.jsonl",
        root / "experiments" / "simulation_regression.json"
    ), indent=2))