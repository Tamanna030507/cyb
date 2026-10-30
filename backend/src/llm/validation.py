from __future__ import annotations
import re
from typing import Any

ALLOWED_CONTAINMENT = {
    "isolate_host",
    "disable_account",
    "block_hash",
    "block_extension",
    "kill_process",
    "snapshot_host",
    "notify_analyst",
    "quarantine_file"
}

DESTRUCTIVE = {"isolate_host", "disable_account", "kill_process"}

SPL_FORBIDDEN = [
    re.compile(r"\|\s*delete\b", re.I),
    re.compile(r"\|\s*outputcsv\b", re.I),
    re.compile(r"\|\s*collect\b", re.I),
    re.compile(r"\|\s*run\b", re.I),
    re.compile(r"\|\s*script\b", re.I),
]

SPL_REQUIRED_HINTS = [
    re.compile(r"\bsearch\b|\bindex\s*=|\bsourcetype\s*=", re.I)
]

def validate_spl(query: str) -> dict[str, Any]:
    if not query or not query.strip():
        return {"valid": False, "reason": "empty"}
    q = query.strip()
    for pat in SPL_FORBIDDEN:
        if pat.search(q):
            return {"valid": False, "reason": f"forbidden operator matched: {pat.pattern}"}
    if not any(p.search(q) for p in SPL_REQUIRED_HINTS):
        return {"valid": False, "reason": "missing search/index/sourcetype anchor"}
    if len(q) > 4000:
        return {"valid": False, "reason": "query too long"}
    return {"valid": True, "reason": "ok"}

def gate_containment(actions: list[str], require_human: bool = True) -> dict[str, Any]:
    approved = []
    rejected = []
    needs_approval = []
    for a in actions:
        key = a.strip().lower().replace(" ", "_")
        if key not in ALLOWED_CONTAINMENT:
            rejected.append({"action": a, "reason": "not in allowlist"})
            continue
        if key in DESTRUCTIVE and require_human:
            needs_approval.append({"action": a, "reason": "destructive requires human approval"})
        else:
            approved.append(a)
    return {
        "approved": approved,
        "needs_human_approval": needs_approval,
        "rejected": rejected
    }

def ground_explanation(
    text: str,
    shap_features: list[tuple[str, float]],
    observed_events: list[str]
) -> dict[str, Any]:
    text_l = text.lower()
    cited_features = []
    for name, val in shap_features:
        if name.lower() in text_l or name.replace("_", " ") in text_l:
            cited_features.append(name)
    cited_events = []
    for ev in observed_events:
        token = ev.lower().split()[0] if ev else ""
        if token and token in text_l:
            cited_events.append(ev)
    grounded = len(cited_features) > 0 or len(cited_events) > 0
    return {
        "grounded": grounded,
        "cited_features": cited_features,
        "cited_events": cited_events,
        "score": (len(cited_features) + len(cited_events)) / max(len(shap_features) + len(observed_events), 1)
    }