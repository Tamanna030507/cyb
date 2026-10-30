from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from data.generator import EventGenerator
from eval.evaluate import load_events, group_by_host, time_based_split, check_temporal_leakage

def test_temporal_leakage_passes(tmp_path):
    out = tmp_path / "syn"
    EventGenerator(seed=7).generate_dataset(n_benign_hosts=20, n_attack_hosts=8, out_dir=out)
    events = load_events(out / "events.jsonl")
    host_events = group_by_host(events)
    train, test = time_based_split(host_events)
    train_events = [e for evs in train.values() for e in evs]
    test_events = [e for evs in test.values() for e in evs]
    result = check_temporal_leakage(train_events, test_events)
    assert result["ok"] is True
    assert result["leaked"] is False

def test_labels_exist(tmp_path):
    out = tmp_path / "syn2"
    EventGenerator(seed=3).generate_dataset(n_benign_hosts=10, n_attack_hosts=4, out_dir=out)
    events = load_events(out / "events.jsonl")
    assert any(e.get("label") == 1 for e in events)
    assert any(e.get("label") == 0 for e in events)