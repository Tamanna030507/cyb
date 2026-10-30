from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import BernoulliNB
from sklearn.metrics import accuracy_score, roc_auc_score
import joblib

def _synth_flows(n: int, malicious: bool, rng: np.random.Generator) -> np.ndarray:
    rows = []
    for _ in range(n):
        if malicious:
            sizes = rng.normal(800, 120, size=8).clip(40, 1500)
            gaps = rng.exponential(0.02, size=8)
            ratio = rng.uniform(0.7, 0.95)
            ja3_bucket = rng.integers(0, 5)
        else:
            sizes = rng.normal(600, 200, size=8).clip(40, 1500)
            gaps = rng.exponential(0.08, size=8)
            ratio = rng.uniform(0.35, 0.65)
            ja3_bucket = rng.integers(0, 12)
        feat = np.concatenate([
            sizes / 1500.0,
            gaps,
            [ratio, ja3_bucket / 12.0, float(malicious)]
        ])
        rows.append(feat[:-1])
    return np.vstack(rows)

def train_eve_prototype(out_path: Path, seed: int = 42) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    X_pos = _synth_flows(400, True, rng)
    X_neg = _synth_flows(400, False, rng)
    X = np.vstack([X_pos, X_neg])
    y = np.array([1] * len(X_pos) + [0] * len(X_neg))
    idx = rng.permutation(len(y))
    X, y = X[idx], y[idx]
    split = int(0.75 * len(y))
    Xtr, Xte, ytr, yte = X[:split], X[split:], y[:split], y[split:]

    nb = BernoulliNB(alpha=0.5)
    Xtr_b = (Xtr > np.median(Xtr, axis=0)).astype(int)
    Xte_b = (Xte > np.median(Xtr, axis=0)).astype(int)
    nb.fit(Xtr_b, ytr)
    nb_pred = nb.predict(Xte_b)
    nb_proba = nb.predict_proba(Xte_b)[:, 1]

    lr = LogisticRegression(max_iter=400)
    lr.fit(Xtr, ytr)
    lr_pred = lr.predict(Xte)
    lr_proba = lr.predict_proba(Xte)[:, 1]

    result = {
        "inspired_by": "Cisco Encrypted Visibility Engine (metadata-only classification)",
        "features": "packet size sequence, inter-arrival gaps, direction ratio, TLS fingerprint bucket",
        "weighted_naive_bayes": {
            "accuracy": float(accuracy_score(yte, nb_pred)),
            "auc": float(roc_auc_score(yte, nb_proba))
        },
        "logistic_regression": {
            "accuracy": float(accuracy_score(yte, lr_pred)),
            "auc": float(roc_auc_score(yte, lr_proba))
        },
        "note": "Toy prototype on simulated encrypted-flow metadata. Not production EVE."
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    joblib.dump({"nb": nb, "lr": lr, "median": np.median(Xtr, axis=0)}, out_path.with_suffix(".joblib"))
    return result

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(train_eve_prototype(root / "experiments" / "eve_results.json"), indent=2))