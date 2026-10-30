from __future__ import annotations
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
import numpy as np

BENIGN_PROCESSES = [
    "explorer.exe", "svchost.exe", "chrome.exe", "outlook.exe", "teams.exe",
    "code.exe", "python.exe", "node.exe", "SearchIndexer.exe", "RuntimeBroker.exe",
    "OneDrive.exe", "MsMpEng.exe", "Taskmgr.exe", "powershell.exe", "cmd.exe"
]

ATTACK_PROCESSES = [
    "procdump.exe", "mimikatz.exe", "psexec.exe", "vssadmin.exe", "wevtutil.exe",
    "ransom.exe", "encryptor.exe", "locker.exe"
]

RANSOM_EXTS = [".locked", ".encrypted", ".ryuk", ".conti", ".lockbit", ".blackcat", ".wncry"]

MITRE_WEIGHTS = {
    "T1087": 0.6, "T1059": 0.7, "T1003": 0.95, "T1021": 0.85,
    "T1070": 0.8, "T1486": 0.97, "T1547": 0.75, "T1053": 0.7
}

class EventGenerator:
    def __init__(self, seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.random = random.Random(seed)

    def _ts(self, base: datetime, offset_seconds: float) -> str:
        return (base + timedelta(seconds=offset_seconds)).isoformat() + "Z"

    def benign_host_session(self, host_id: str, user_id: str, start: datetime, n_events: int = 40) -> list[dict]:
        events = []
        t = 0.0
        for _ in range(n_events):
            t += self.rng.exponential(8)
            proc = self.random.choice(BENIGN_PROCESSES)
            etype = self.random.choices(
                ["process_spawn", "file_open", "network_flow", "file_write"],
                weights=[0.45, 0.25, 0.2, 0.1]
            )[0]
            e: dict[str, Any] = {
                "event_id": str(uuid.uuid4()),
                "timestamp": self._ts(start, t),
                "host_id": host_id,
                "user_id": user_id,
                "event_type": etype,
                "label": 0,
                "mitre": [],
                "stage": "benign"
            }
            if etype == "process_spawn":
                e["process_name"] = proc
                e["command_line"] = f"{proc} /normal"
            elif etype == "file_open" or etype == "file_write":
                e["path"] = f"C:\\Users\\{user_id}\\Documents\\file_{self.random.randint(1,200)}.docx"
            elif etype == "network_flow":
                e["destination"] = f"10.{self.random.randint(0,20)}.{self.random.randint(0,255)}.{self.random.randint(1,254)}"
                e["bytes_sent"] = int(self.rng.integers(100, 50000))
                e["bytes_recv"] = int(self.rng.integers(100, 30000))
            events.append(e)
        return events

    def attack_sequence(self, host_id: str, user_id: str, start: datetime, style: str = "standard") -> list[dict]:
        events = []
        t = 0.0
        stages = [
            ("Discovery", ["T1087"], [
                ("process_spawn", "whoami.exe", "whoami /all"),
                ("process_spawn", "net.exe", "net user /domain"),
                ("process_spawn", "nltest.exe", "nltest /dclist")
            ]),
            ("Credential Access", ["T1003"], [
                ("process_spawn", "procdump.exe", "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp"),
                ("process_spawn", "mimikatz.exe", "mimikatz.exe privilege::debug sekurlsa::logonpasswords")
            ]),
            ("Defense Evasion", ["T1070"], [
                ("process_spawn", "wevtutil.exe", "wevtutil.exe cl Security"),
                ("process_spawn", "wevtutil.exe", "wevtutil.exe cl System")
            ]),
            ("Lateral Movement", ["T1021"], [
                ("process_spawn", "psexec.exe", "psexec \\\\dc-02 cmd.exe"),
                ("network_flow", None, None)
            ]),
            ("Impact", ["T1486"], [
                ("process_spawn", "vssadmin.exe", "vssadmin delete shadows /all /quiet"),
                ("file_rename", None, None),
                ("file_rename", None, None),
                ("file_rename", None, None),
                ("file_write", None, None)
            ])
        ]

        if style == "evasive":
            stages = [
                ("Discovery", ["T1087"], [
                    ("process_spawn", "whoami.exe", "whoami")
                ]),
                ("Credential Access", ["T1003"], [
                    ("process_spawn", "procdump.exe", "procdump.exe -ma lsass.exe C:\\temp\\x.dmp")
                ]),
                ("Impact", ["T1486"], [
                    ("process_spawn", "vssadmin.exe", "vssadmin delete shadows /all /quiet"),
                    ("file_rename", None, None),
                    ("file_rename", None, None)
                ])
            ]

        for stage_name, mitre, actions in stages:
            for action in actions:
                delay = self.rng.uniform(15, 90) if style != "evasive" else self.rng.uniform(40, 180)
                t += delay
                etype, proc, cmd = action
                e: dict[str, Any] = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": self._ts(start, t),
                    "host_id": host_id,
                    "user_id": user_id,
                    "event_type": etype,
                    "label": 1,
                    "mitre": mitre,
                    "stage": stage_name
                }
                if etype == "process_spawn":
                    e["process_name"] = proc
                    e["command_line"] = cmd
                elif etype == "file_rename":
                    base = f"C:\\Users\\{user_id}\\Documents\\doc_{self.random.randint(1,50)}"
                    ext = self.random.choice(RANSOM_EXTS)
                    e["path"] = base + ".docx"
                    e["new_path"] = base + ext
                elif etype == "file_write":
                    e["path"] = f"C:\\Users\\{user_id}\\Desktop\\note{self.random.choice(RANSOM_EXTS)}"
                    e["content_sample"] = "A" * 120 + "".join(chr(self.random.randint(0, 255)) for _ in range(80))
                elif etype == "network_flow":
                    e["destination"] = f"{self.random.randint(1,200)}.{self.random.randint(1,200)}.{self.random.randint(1,200)}.{self.random.randint(1,200)}"
                    e["bytes_sent"] = int(self.rng.integers(100000, 5000000))
                    e["bytes_recv"] = int(self.rng.integers(200, 5000))
                events.append(e)
        return events

    def generate_dataset(
        self,
        n_benign_hosts: int = 80,
        n_attack_hosts: int = 25,
        evasive_ratio: float = 0.3,
        out_dir: str | Path = "data/synthetic"
    ) -> Path:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        all_events = []
        train_start = datetime(2025, 6, 1, 8, 0, 0)
        test_start = datetime(2025, 6, 10, 8, 0, 0)
        n_ben_train = int(n_benign_hosts * 0.75)
        n_att_train = int(n_attack_hosts * 0.75)

        for i in range(n_benign_hosts):
            host = f"host-benign-{i:03d}"
            user = f"user{i % 20}"
            if i < n_ben_train:
                start = train_start + timedelta(hours=float(i * 3 + self.rng.uniform(0, 2)))
            else:
                start = test_start + timedelta(hours=float((i - n_ben_train) * 3 + self.rng.uniform(0, 2)))
            all_events.extend(self.benign_host_session(host, user, start, n_events=int(self.rng.integers(30, 70))))

        for i in range(n_attack_hosts):
            host = f"host-attack-{i:03d}"
            user = f"svc{i % 8}"
            if i < n_att_train:
                start = train_start + timedelta(hours=float(50 + i * 4 + self.rng.uniform(0, 1)))
            else:
                start = test_start + timedelta(hours=float(20 + (i - n_att_train) * 4 + self.rng.uniform(0, 1)))
            style = "evasive" if self.rng.random() < evasive_ratio else "standard"
            all_events.extend(self.attack_sequence(host, user, start, style=style))
            all_events.extend(self.benign_host_session(host, user, start + timedelta(hours=3), n_events=12))

        all_events.sort(key=lambda e: e["timestamp"])
        path = out / "events.jsonl"
        with path.open("w") as f:
            for e in all_events:
                f.write(json.dumps(e) + "\n")

        meta = {
            "n_events": len(all_events),
            "n_benign_hosts": n_benign_hosts,
            "n_attack_hosts": n_attack_hosts,
            "evasive_ratio": evasive_ratio,
            "train_window": "2025-06-01 to 2025-06-09",
            "test_window": "2025-06-10 onwards",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "label_logic": "Deterministic from generator stage. Attack sequences labeled 1, benign sessions labeled 0.",
            "imbalance_note": "Controlled synthetic ratio. Real environments are far more imbalanced.",
            "temporal_design": "Train hosts only in early window, test hosts only in later window. No timestamp overlap by construction."
        }
        with (out / "dataset_card.json").open("w") as f:
            json.dump(meta, f, indent=2)
        return path

if __name__ == "__main__":
    gen = EventGenerator(seed=42)
    p = gen.generate_dataset()
    print(p)