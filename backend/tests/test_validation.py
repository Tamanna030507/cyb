from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm.validation import validate_spl, gate_containment, ground_explanation

def test_spl_rejects_delete():
    r = validate_spl("search index=main | delete")
    assert r["valid"] is False

def test_spl_accepts_search():
    r = validate_spl("search earliest=-15m index=main sourcetype=WinEventLog:Security | table _time host")
    assert r["valid"] is True

def test_containment_gates_destructive():
    r = gate_containment(["isolate_host", "block_extension"], require_human=True)
    assert any(x["action"] == "isolate_host" for x in r["needs_human_approval"])
    assert "block_extension" in r["approved"]

def test_containment_rejects_unknown():
    r = gate_containment(["format_disk"], require_human=True)
    assert len(r["rejected"]) == 1

def test_grounding_detects_feature_mention():
    r = ground_explanation(
        "encrypt_ext_hits and shadow_delete_hits indicate ransomware",
        [("encrypt_ext_hits", 0.3), ("shadow_delete_hits", 0.2)],
        ["vssadmin delete shadows"]
    )
    assert r["grounded"] is True