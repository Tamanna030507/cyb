from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import numpy as np

from features.extract import extract_features
from models.train import DetectionModel
from eval.evaluate import load_events, group_by_host, time_based_split

def run_poisoning_analysis(
    data_path: Path,
    out_path: Path,
    poison_rates: list[float] | None = None,
    n_cycles: int = 3
) -> dict[str, Any]:
    if poison_rates is None:
        poison_rates = [0.0, 0.1, 0.25, 0.5]
    events = load_events(data_path)
    host_events = group_by_host(events)
    train_h, test_h = time_based_split(host_events)

    def build_xy(groups):
        X, y = [], []
        for h, evs in groups.items():
            X.append(extract_features(evs))
            y.append(1 if any(e.get("label") == 1 for e in evs) else 0)
        return np.vstack(X), np.array(y)

    X_train, y_train = build_xy(train_h)
    X_test, y_test = build_xy(test_h)

    results = []
    for rate in poison_rates:
        X = X_train.copy()
        y = y_train.copy()
        pos_idx = np.where(y == 1)[0]
        n_poison = int(len(pos_idx) * rate)
        if n_poison > 0:
            chosen = np.random.default_rng(42).choice(pos_idx, size=n_poison, replace=False)
            y[chosen] = 0
        model = DetectionModel()
        model.fit(X, y)
        scores = model.score(X_test)
        preds = (scores >= 0.45).astype(int)
        recall = float(preds[y_test == 1].mean()) if (y_test == 1).any() else 0.0
        results.append({
            "poison_rate": rate,
            "n_poisoned_labels": n_poison,
            "test_recall": round(recall, 4),
            "mean_score_on_attacks": round(float(scores[y_test == 1].mean()) if (y_test == 1).any() else 0.0, 4)
        })

    out = {
        "description": "Simulated feedback-loop poisoning: true-positive labels flipped to false-positive at given rates, then model retrained.",
        "results": results,
        "takeaway": "Higher poison rates degrade recall. Provenance-tracked feedback is required before closed-loop retraining."
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    return out

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(run_poisoning_analysis(
        root / "data" / "synthetic" / "events.jsonl",
        root / "experiments" / "poisoning_results.json"
    ), indent=2))