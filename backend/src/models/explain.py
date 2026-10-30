from __future__ import annotations
from typing import Any
import numpy as np

from features.extract import FEATURE_NAMES

FEATURE_MITRE = {
    "encrypt_ext_hits": ["T1486"],
    "shadow_delete_hits": ["T1486", "T1490"],
    "entropy_spike_count": ["T1486"],
    "lsass_hits": ["T1003"],
    "log_clear_hits": ["T1070"],
    "persistence_hits": ["T1547", "T1053"],
    "lateral_hits": ["T1021"],
    "obfuscation_hits": ["T1059", "T1027"],
    "file_rename_rate_5m": ["T1486"],
    "file_write_rate_5m": ["T1486"],
    "rare_proc_hits": ["T1059", "T1204"],
    "integrity_jump_hits": ["T1134"],
    "network_exfil_bytes": ["T1041"],
    "service_mod_hits": ["T1543"],
}

def approximate_shap(model, X_row: np.ndarray, baseline: np.ndarray | None = None) -> list[dict[str, Any]]:
    if baseline is None:
        baseline = np.zeros_like(X_row)
    base_score = float(model.score(baseline.reshape(1, -1))[0])
    full_score = float(model.score(X_row.reshape(1, -1))[0])
    contribs = []
    for i, name in enumerate(FEATURE_NAMES):
        masked = X_row.copy()
        masked[i] = baseline[i]
        masked_score = float(model.score(masked.reshape(1, -1))[0])
        contrib = full_score - masked_score
        contribs.append({
            "feature": name,
            "value": float(X_row[i]),
            "contribution": round(contrib, 4),
            "mitre": FEATURE_MITRE.get(name, [])
        })
    contribs.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    return contribs

def explanation_text(contribs: list[dict[str, Any]], top_k: int = 5) -> str:
    parts = []
    for c in contribs[:top_k]:
        if abs(c["contribution"]) < 0.01:
            continue
        mitre = ", ".join(c["mitre"]) if c["mitre"] else "general"
        parts.append(f"{c['feature']}={c['value']:.2f} (contrib {c['contribution']:+.3f}, {mitre})")
    if not parts:
        return "No strong feature contributions above threshold."
    return "Flagged primarily due to: " + "; ".join(parts) + "."