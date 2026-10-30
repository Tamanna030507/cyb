from __future__ import annotations
from typing import Any

def tier_alert(score: float) -> dict[str, Any]:
    if score >= 0.85:
        return {
            "tier": "auto_contain_candidate",
            "action": "queue_isolation_approval",
            "analyst_required": True,
            "priority": 1,
            "sla_minutes": 5
        }
    if score >= 0.65:
        return {
            "tier": "analyst_review",
            "action": "open_investigation",
            "analyst_required": True,
            "priority": 2,
            "sla_minutes": 30
        }
    if score >= 0.45:
        return {
            "tier": "watch",
            "action": "log_and_monitor",
            "analyst_required": False,
            "priority": 3,
            "sla_minutes": 240
        }
    return {
        "tier": "log_only",
        "action": "store",
        "analyst_required": False,
        "priority": 4,
        "sla_minutes": None
    }

def triage_load(n_alerts: int, fpr: float, analyst_capacity_per_hour: int = 12) -> dict[str, Any]:
    expected_fp = n_alerts * fpr
    hours_needed = n_alerts / max(analyst_capacity_per_hour, 1)
    return {
        "alerts": n_alerts,
        "expected_false_positives": round(expected_fp, 1),
        "analyst_hours": round(hours_needed, 2),
        "capacity_per_hour": analyst_capacity_per_hour,
        "overloaded": hours_needed > 8
    }