from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_recall_curve, average_precision_score, roc_auc_score,
    confusion_matrix, f1_score, precision_score, recall_score
)
import xgboost as xgb

from features.extract import FEATURE_NAMES, extract_features

class DetectionModel:
    def __init__(self):
        self.scaler = StandardScaler()
        self.iso = IsolationForest(contamination=0.03, random_state=42, n_jobs=-1)
        self.rf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
        self.gbm = GradientBoostingClassifier(n_estimators=150, max_depth=5, random_state=42)
        self.xgb = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.08,
            subsample=0.85, colsample_bytree=0.85, random_state=42,
            eval_metric="logloss"
        )
        self.mlp = MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=400, random_state=42)
        self.ready = False
        self.feature_names = FEATURE_NAMES

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.iso.fit(Xs[y == 0] if (y == 0).any() else Xs)
        self.rf.fit(Xs, y)
        self.gbm.fit(Xs, y)
        self.xgb.fit(Xs, y)
        self.mlp.fit(Xs, y)
        self.ready = True

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self.ready:
            return np.zeros(len(X))
        Xs = self.scaler.transform(X)
        iso_s = -self.iso.decision_function(Xs)
        iso_s = (iso_s - iso_s.min()) / (iso_s.max() - iso_s.min() + 1e-9)
        rf_s = self.rf.predict_proba(Xs)[:, 1]
        gbm_s = self.gbm.predict_proba(Xs)[:, 1]
        xgb_s = self.xgb.predict_proba(Xs)[:, 1]
        mlp_s = self.mlp.predict_proba(Xs)[:, 1]
        return 0.10 * iso_s + 0.20 * rf_s + 0.20 * gbm_s + 0.35 * xgb_s + 0.15 * mlp_s

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.score(X) >= threshold).astype(int)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "scaler": self.scaler,
            "iso": self.iso,
            "rf": self.rf,
            "gbm": self.gbm,
            "xgb": self.xgb,
            "mlp": self.mlp,
            "feature_names": self.feature_names
        }, path)

    def load(self, path: str | Path) -> None:
        data = joblib.load(path)
        self.scaler = data["scaler"]
        self.iso = data["iso"]
        self.rf = data["rf"]
        self.gbm = data["gbm"]
        self.xgb = data["xgb"]
        self.mlp = data["mlp"]
        self.feature_names = data.get("feature_names", FEATURE_NAMES)
        self.ready = True

def rules_baseline(events: list[dict]) -> float:
    score = 0.0
    for e in events:
        cmd = (e.get("command_line") or "") + " " + (e.get("process_name") or "")
        path = (e.get("new_path") or e.get("path") or "").lower()
        if "vssadmin" in cmd.lower() and "delete" in cmd.lower():
            score += 0.35
        if "lsass" in cmd.lower() or "mimikatz" in cmd.lower() or "procdump" in cmd.lower():
            score += 0.30
        if any(path.endswith(ext) for ext in [".locked", ".ryuk", ".conti", ".lockbit", ".encrypted"]):
            score += 0.25
        if "wevtutil" in cmd.lower() and "cl" in cmd.lower():
            score += 0.15
        if "psexec" in cmd.lower():
            score += 0.20
    return min(score, 1.0)

def sigma_like_baseline(events: list[dict]) -> float:
    hits = 0
    checks = [
        lambda e: "vssadmin" in (e.get("command_line") or "").lower() and "shadows" in (e.get("command_line") or "").lower(),
        lambda e: any(x in (e.get("command_line") or "").lower() for x in ["procdump", "mimikatz", "lsass"]),
        lambda e: any((e.get("new_path") or "").lower().endswith(ext) for ext in [".locked", ".ryuk", ".conti", ".lockbit"]),
        lambda e: "wevtutil" in (e.get("command_line") or "").lower(),
        lambda e: "psexec" in (e.get("command_line") or "").lower()
    ]
    for e in events:
        for c in checks:
            if c(e):
                hits += 1
    return min(hits / 3.0, 1.0)

def evaluate_model(
    model: DetectionModel,
    X: np.ndarray,
    y: np.ndarray,
    host_events: dict[str, list[dict]] | None = None,
    threshold: float = 0.5
) -> dict[str, Any]:
    scores = model.score(X)
    preds = (scores >= threshold).astype(int)
    pr_auc = float(average_precision_score(y, scores)) if y.sum() > 0 else 0.0
    try:
        roc = float(roc_auc_score(y, scores))
    except Exception:
        roc = 0.0
    prec = float(precision_score(y, preds, zero_division=0))
    rec = float(recall_score(y, preds, zero_division=0))
    f1 = float(f1_score(y, preds, zero_division=0))
    cm = confusion_matrix(y, preds).tolist()

    fpr_at_90 = None
    precisions, recalls, thresholds = precision_recall_curve(y, scores)
    for p, r, t in zip(precisions, recalls, list(thresholds) + [1.0]):
        if r >= 0.90:
            preds_t = (scores >= t).astype(int)
            fp = ((preds_t == 1) & (y == 0)).sum()
            tn = ((preds_t == 0) & (y == 0)).sum()
            fpr_at_90 = float(fp / (fp + tn + 1e-9))
            break

    rules_scores = []
    sigma_scores = []
    if host_events:
        for h in host_events:
            rules_scores.append(rules_baseline(host_events[h]))
            sigma_scores.append(sigma_like_baseline(host_events[h]))
        rules_preds = (np.array(rules_scores) >= 0.5).astype(int)
        sigma_preds = (np.array(sigma_scores) >= 0.5).astype(int)
        rules_rec = float(recall_score(y, rules_preds, zero_division=0))
        sigma_rec = float(recall_score(y, sigma_preds, zero_division=0))
    else:
        rules_rec = sigma_rec = 0.0

    return {
        "pr_auc": pr_auc,
        "roc_auc": roc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr_at_90_recall": fpr_at_90,
        "confusion_matrix": cm,
        "rules_only_recall": rules_rec,
        "sigma_baseline_recall": sigma_rec,
        "threshold": threshold,
        "n_samples": int(len(y)),
        "n_positive": int(y.sum())
    }