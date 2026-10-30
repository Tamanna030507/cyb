from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path
from typing import Any
import numpy as np

from data.generator import EventGenerator
from features.extract import extract_features
from models.train import DetectionModel, evaluate_model
from eval.evaluate import group_by_host, time_based_split, load_events

def run_evasion_experiment(model_path: Path, data_path: Path, out_path: Path) -> dict[str, Any]:
    events = load_events(data_path)
    host_events = group_by_host(events)
    model = DetectionModel()
    model.load(model_path)

    standard = {}
    evasive = {}
    for h, evs in host_events.items():
        if not any(e.get("label") == 1 for e in evs):
            continue
        stages = {e.get("stage") for e in evs}
        cmds = " ".join((e.get("command_line") or "") for e in evs).lower()
        is_evasive = "whoami /all" not in cmds and len([e for e in evs if e.get("label") == 1]) <= 8
        if is_evasive:
            evasive[h] = evs
        else:
            standard[h] = evs

    def score_hosts(groups: dict) -> dict[str, Any]:
        if not groups:
            return {"n": 0, "recall": 0.0, "mean_score": 0.0}
        X, y = [], []
        for h, evs in groups.items():
            X.append(extract_features(evs))
            y.append(1)
        X = np.vstack(X)
        y = np.array(y)
        scores = model.score(X)
        preds = (scores >= 0.45).astype(int)
        return {
            "n": int(len(y)),
            "recall": float(preds.mean()),
            "mean_score": float(scores.mean()),
            "scores": [round(float(s), 3) for s in scores]
        }

    std_res = score_hosts(standard)
    eva_res = score_hosts(evasive)
    drop = std_res["recall"] - eva_res["recall"] if std_res["n"] and eva_res["n"] else 0.0

    ablation = {}
    if standard:
        sample_h = next(iter(standard))
        base_vec = extract_features(standard[sample_h])
        base_score = float(model.score(base_vec.reshape(1, -1))[0])
        from features.extract import FEATURE_NAMES
        for i, name in enumerate(FEATURE_NAMES):
            masked = base_vec.copy()
            masked[i] = 0.0
            s = float(model.score(masked.reshape(1, -1))[0])
            ablation[name] = round(base_score - s, 4)

    result = {
        "standard_attacks": std_res,
        "evasive_attacks": eva_res,
        "recall_drop": round(drop, 4),
        "feature_ablation_impact": dict(sorted(ablation.items(), key=lambda x: -abs(x[1]))[:10]),
        "summary": f"Standard recall {std_res['recall']:.2f}, evasive recall {eva_res['recall']:.2f}, drop {drop:.2f}"
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(run_evasion_experiment(
        root / "models" / "detector.joblib",
        root / "data" / "synthetic" / "events.jsonl",
        root / "experiments" / "evasion_results.json"
    ), indent=2))