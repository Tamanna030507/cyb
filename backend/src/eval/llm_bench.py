from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from llm.validation import validate_spl, gate_containment, ground_explanation

CASES = [
    {
        "id": "c1",
        "spl": "search earliest=-30m index=main sourcetype=WinEventLog:Security | table _time host",
        "expect_valid": True,
        "actions": ["isolate_host", "block_extension"],
        "text": "Flagged due to encrypt_ext_hits and shadow_delete_hits mapped to T1486",
        "shap": [{"name": "encrypt_ext_hits", "value": 0.3}, {"name": "shadow_delete_hits", "value": 0.2}],
        "events": ["vssadmin delete shadows", "file rename .locked"]
    },
    {
        "id": "c2",
        "spl": "search index=main | delete",
        "expect_valid": False,
        "actions": ["format_disk"],
        "text": "The system is compromised by advanced persistent threats from nation states",
        "shap": [{"name": "lsass_hits", "value": 0.4}],
        "events": ["procdump lsass"]
    },
    {
        "id": "c3",
        "spl": "index=wineventlog EventCode=4688 CommandLine=*vssadmin*",
        "expect_valid": True,
        "actions": ["notify_analyst", "quarantine_file"],
        "text": "lsass_hits contribution indicates credential access T1003",
        "shap": [{"name": "lsass_hits", "value": 0.5}],
        "events": ["procdump.exe -ma lsass.exe"]
    },
    {
        "id": "c4",
        "spl": "| outputcsv evil.csv",
        "expect_valid": False,
        "actions": ["kill_process", "disable_account"],
        "text": "Random unrelated commentary about weather",
        "shap": [{"name": "file_rename_rate_5m", "value": 0.2}],
        "events": ["rename to .ryuk"]
    },
    {
        "id": "c5",
        "spl": "search earliest=-1h sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "expect_valid": True,
        "actions": ["snapshot_host"],
        "text": "file_rename_rate_5m and encrypt_ext_hits support ransomware impact",
        "shap": [{"name": "file_rename_rate_5m", "value": 0.25}, {"name": "encrypt_ext_hits", "value": 0.3}],
        "events": ["file_rename", "note.locked"]
    }
]

def run_llm_benchmark(out_path: Path) -> dict[str, Any]:
    valid_correct = 0
    grounded = 0
    gated_ok = 0
    details = []
    for c in CASES:
        spl_res = validate_spl(c["spl"])
        valid_match = spl_res["valid"] == c["expect_valid"]
        if valid_match:
            valid_correct += 1
        gate = gate_containment(c["actions"], require_human=True)
        gate_sensible = len(gate["rejected"]) > 0 or len(gate["needs_human_approval"]) > 0 or len(gate["approved"]) > 0
        if gate_sensible:
            gated_ok += 1
        shap = [(x["name"], x["value"]) for x in c["shap"]]
        g = ground_explanation(c["text"], shap, c["events"])
        if g["grounded"]:
            grounded += 1
        details.append({
            "id": c["id"],
            "spl_valid": spl_res["valid"],
            "spl_expected": c["expect_valid"],
            "spl_match": valid_match,
            "grounded": g["grounded"],
            "gate": gate
        })
    n = len(CASES)
    out = {
        "n_cases": n,
        "spl_validity_accuracy": round(valid_correct / n, 3),
        "grounding_rate": round(grounded / n, 3),
        "gating_coverage": round(gated_ok / n, 3),
        "details": details,
        "note": "Synthetic benchmark of validation/gating/grounding logic. Not a live LLM call benchmark."
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    return out

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(run_llm_benchmark(root / "experiments" / "llm_bench_results.json"), indent=2))