from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import numpy as np
from sklearn.metrics import average_precision_score, precision_score, recall_score, f1_score

from data.clear_schema import generate_clear_mini, load_clear_csv
from features.sequential import build_xy_from_clear
from models.train import DetectionModel

def _fit_score(X_train, y_train, X_test, y_test) -> dict[str, Any]:
    model = DetectionModel()
    model.fit(X_train, y_train)
    scores = model.score(X_test)
    preds = (scores >= 0.45).astype(int)
    return {
        "pr_auc": float(average_precision_score(y_test, scores)) if y_test.sum() else 0.0,
        "precision": float(precision_score(y_test, preds, zero_division=0)),
        "recall": float(recall_score(y_test, preds, zero_division=0)),
        "f1": float(f1_score(y_test, preds, zero_division=0)),
        "n_test": int(len(y_test)),
        "n_pos": int(y_test.sum())
    }

def run_clear_evaluation(out_dir: Path, data_csv: Path | None = None) -> dict[str, Any]:
    if data_csv is None or not Path(data_csv).exists():
        data_csv = generate_clear_mini(out_dir / "clear_mini")
    rows = load_clear_csv(data_csv)
    X, y, splits, families = build_xy_from_clear(rows, window=50)

    known_mask = np.array([s in ("known", "benign") for s in splits])
    unknown_mask = np.array([s in ("unknown", "benign") for s in splits])
    train_idx = np.where(np.array(splits) != "unknown")[0]
    test_known_idx = np.where(np.array(splits) == "known")[0]
    test_unknown_idx = np.where(np.array(splits) == "unknown")[0]
    benign_idx = np.where(y == 0)[0]

    rng = np.random.default_rng(42)
    train_benign = rng.choice(benign_idx, size=min(len(benign_idx), max(len(train_idx) // 2, 10)), replace=False)
    train_ids = np.unique(np.concatenate([train_idx, train_benign]))

    X_train, y_train = X[train_ids], y[train_ids]

    known_test_ids = np.unique(np.concatenate([
        test_known_idx,
        rng.choice(benign_idx, size=min(len(benign_idx), max(len(test_known_idx), 5)), replace=False)
    ]))
    unknown_test_ids = np.unique(np.concatenate([
        test_unknown_idx,
        rng.choice(benign_idx, size=min(len(benign_idx), max(len(test_unknown_idx), 5)), replace=False)
    ]))

    known_metrics = _fit_score(X_train, y_train, X[known_test_ids], y[known_test_ids])
    model = DetectionModel()
    model.fit(X_train, y_train)
    unk_scores = model.score(X[unknown_test_ids])
    unk_preds = (unk_scores >= 0.45).astype(int)
    y_unk = y[unknown_test_ids]
    unknown_metrics = {
        "pr_auc": float(average_precision_score(y_unk, unk_scores)) if y_unk.sum() else 0.0,
        "precision": float(precision_score(y_unk, unk_preds, zero_division=0)),
        "recall": float(recall_score(y_unk, unk_preds, zero_division=0)),
        "f1": float(f1_score(y_unk, unk_preds, zero_division=0)),
        "n_test": int(len(y_unk)),
        "n_pos": int(y_unk.sum())
    }

    poison_rates = [0.0, 0.25, 0.5]
    poison_results = []
    pos = np.where(y_train == 1)[0]
    for rate in poison_rates:
        y_p = y_train.copy()
        n_p = int(len(pos) * rate)
        if n_p > 0:
            flip = rng.choice(pos, size=n_p, replace=False)
            y_p[flip] = 0
        m = DetectionModel()
        m.fit(X_train, y_p)
        sc = m.score(X[known_test_ids])
        pr = (sc >= 0.45).astype(int)
        poison_results.append({
            "poison_rate": rate,
            "recall": float(recall_score(y[known_test_ids], pr, zero_division=0))
        })

    result = {
        "data": str(data_csv),
        "schema": "CLEAR command-level mini sample",
        "known_variants": known_metrics,
        "unknown_variants": unknown_metrics,
        "poisoning_on_clear_schema": poison_results,
        "disclaimer": "Mini CLEAR-schema sample for pipeline credibility. Full CLEAR is on Kaggle; re-run loader on real subset for production claims."
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "clear_eval_results.json").write_text(json.dumps(result, indent=2))
    model_path = out_dir.parent.parent / "models" / "clear_detector.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(model_path)
    return result

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(run_clear_evaluation(root / "experiments"), indent=2))