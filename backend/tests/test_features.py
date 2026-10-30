from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import numpy as np

from features.extract import extract_features, FEATURE_NAMES

def test_feature_vector_length():
    events = [
        {"event_type": "process_spawn", "command_line": "vssadmin delete shadows /all", "process_name": "vssadmin.exe", "timestamp": "2025-06-01T10:00:00Z"},
        {"event_type": "file_rename", "path": "a.docx", "new_path": "a.docx.locked", "timestamp": "2025-06-01T10:01:00Z"},
    ]
    vec = extract_features(events)
    assert vec.shape == (len(FEATURE_NAMES),)
    assert vec[FEATURE_NAMES.index("shadow_delete_hits")] >= 1
    assert vec[FEATURE_NAMES.index("encrypt_ext_hits")] >= 1

def test_empty_events():
    vec = extract_features([])
    assert vec.shape == (len(FEATURE_NAMES),)
    assert np.all(vec == 0)