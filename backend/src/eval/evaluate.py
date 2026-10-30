from __future__ import annotations
import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
import numpy as np

from data.generator import EventGenerator
from features.extract import extract_features, FEATURE_NAMES
from models.train import DetectionModel, evaluate_model, rules_baseline, sigma_like_baseline

def load_events(path: Path) -> list[dict]:
    events = []
    with path.open() as f:
        for line in f:
            events.append(json.loads(line))
    return events

def group_by_host(events: list[dict]) -> dict[str, list[dict]]:
    g: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        g[e["host_id"]].append(e)
    for h in g:
        g[h].sort(key=lambda x: x["timestamp"])
    return dict(g)

def time_based_split(host_events: dict[str, list[dict]], test_ratio: float = 0.25):
    cutoff = datetime(2025, 6, 10, 0, 0, 0).timestamp()
    train = {}
    test = {}
    for h, evs in host_events.items():
        try:
            first_ts = datetime.fromisoformat(evs[0]["timestamp"].replace("Z", "+00:00")).timestamp()
        except Exception:
            first_ts = 0.0
        if first_ts >= cutoff:
            test[h] = evs
        else:
            train[h] = evs
    if not test or not train:
        hosts = sorted(host_events.keys())
        n_test = max(1, int(len(hosts) * test_ratio))
        test_hosts = set(hosts[-n_test:])
        train = {h: host_events[h] for h in hosts if h not in test_hosts}
        test = {h: host_events[h] for h in hosts if h in test_hosts}
    return train, test

def check_temporal_leakage(train_events: list[dict], test_events: list[dict]) -> dict[str, Any]:
    train_times = []
    test_times = []
    for e in train_events:
        try:
            train_times.append(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    for e in test_events:
        try:
            test_times.append(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    if not train_times or not test_times:
        return {"ok": False, "reason": "empty times"}
    max_train = max(train_times)
    min_test = min(test_times)
    leaked = min_test < max_train
    return {
        "ok": not leaked,
        "max_train_ts": max_train,
        "min_test_ts": min_test,
        "leaked": leaked
    }

def compute_mttd(host_events: dict[str, list[dict]], model: DetectionModel, threshold: float = 0.5) -> float:
    latencies = []
    for host, evs in host_events.items():
        attack_start = None
        for e in evs:
            if e.get("label") == 1:
                try:
                    attack_start = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
                    break
                except Exception:
                    continue
        if attack_start is None:
            continue
        for i in range(1, len(evs) + 1):
            window = evs[:i]
            vec = extract_features(window).reshape(1, -1)
            score = model.score(vec)[0]
            if score >= threshold:
                try:
                    detect_ts = datetime.fromisoformat(evs[i-1]["timestamp"].replace("Z", "+00:00")).timestamp()
                    latencies.append(detect_ts - attack_start)
                except Exception:
                    pass
                break
    return float(np.median(latencies)) if latencies else -1.0

def run_full_evaluation(data_path: Path, model_out: Path, results_out: Path) -> dict[str, Any]:
    events = load_events(data_path)
    host_events = group_by_host(events)
    train_h, test_h = time_based_split(host_events, test_ratio=0.25)

    train_events = [e for evs in train_h.values() for e in evs]
    test_events = [e for evs in test_h.values() for e in evs]
    leakage = check_temporal_leakage(train_events, test_events)

    X_train, y_train = [], []
    for h, evs in train_h.items():
        X_train.append(extract_features(evs))
        y_train.append(1 if any(e.get("label") == 1 for e in evs) else 0)
    X_test, y_test = [], []
    for h, evs in test_h.items():
        X_test.append(extract_features(evs))
        y_test.append(1 if any(e.get("label") == 1 for e in evs) else 0)

    X_train = np.vstack(X_train)
    y_train = np.array(y_train)
    X_test = np.vstack(X_test)
    y_test = np.array(y_test)

    model = DetectionModel()
    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    t0 = time.time()
    _ = model.score(X_test)
    infer_time = (time.time() - t0) / max(len(X_test), 1)

    metrics = evaluate_model(model, X_test, y_test, host_events=test_h, threshold=0.45)
    metrics["train_seconds"] = round(train_time, 3)
    metrics["inference_latency_ms"] = round(infer_time * 1000, 2)
    metrics["mttd_seconds"] = compute_mttd(test_h, model, threshold=0.45)
    metrics["temporal_leakage_check"] = leakage
    cm = metrics["confusion_matrix"]
    fp = cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0
    tp = cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0
    metrics["alert_volume_per_1000"] = round((fp + tp) / max(len(y_test), 1) * 1000, 1)

    model.save(model_out)
    results_out.parent.mkdir(parents=True, exist_ok=True)
    with results_out.open("w") as f:
        json.dump(metrics, f, indent=2)
    return metrics

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    data_path = root / "data" / "synthetic" / "events.jsonl"
    if not data_path.exists():
        gen = EventGenerator(seed=42)
        gen.generate_dataset(out_dir=str(root / "data" / "synthetic"))
    results = run_full_evaluation(
        data_path,
        root / "models" / "detector.joblib",
        root / "experiments" / "eval_results.json"
    )
    print(json.dumps(results, indent=2))