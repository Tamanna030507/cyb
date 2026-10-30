# CYB SOC

**Multi-stage ransomware detection with reproducible evaluation, explainability, tiered alerting and measured feedback-loop risk.**

---

## Why this project?

Most student "cyber ML" repos are just a classifier trained on a public CSV. This is a **system** designed around real SOC (Security Operations Center) constraints:

- **Data Integrity:** Time-separated synthetic data with a **passing temporal leakage check**.
- **Rigor:** Ensemble model evaluated against Rules and Sigma-style baselines.
- **Explainability:** Feature contributions mapped to MITRE ATT&CK techniques.
- **Safety:** SPL validation and destructive-action containment gating for the LLM layer.
- **Security Research:** Feedback-loop **poisoning analysis** and an evasion experiment.
- **Operations:** Tiered alerting + triage load estimates.
- **Product:** FastAPI backend + professional SOC frontend.

---

## 📊 Results (v1.0 Evaluation)

*Note: Until a real-world CLEAR dataset subset is evaluated, the ML metrics below are run on a schema-faithful synthetic sample. The perfect scores on the synthetic sample indicate it is highly separable; the true credibility signals here are the leakage checks, poisoning degradation and LLM gating.*

| Metric | Value | Context |
|--------|-------|---------|
| **Temporal leakage** | **Passed** | Strict time-based train/test split by construction |
| PR-AUC / Precision | 1.00 | *Synthetic sample only (highly separable)* |
| Recall | 0.83 | *Synthetic sample only* |
| Rules-only recall | 1.00 | Baseline shows rules overfit the synthetic sample |
| **Inference latency** | **~1.3 ms** | Measured on local CPU |
| Poisoning @ 0% | Recall 0.83 | Baseline model |
| **Poisoning @ 25%** | **Recall 0.33** | **Critical finding:** 25% label flip causes catastrophic collapse |
| LLM SPL validity | 1.00 | Qwen generates valid, parseable Splunk queries |
| **LLM grounding rate** | **0.60** | Explanation matches actual model features 60% of the time |
| **Containment gating** | **1.00** | Destructive actions blocked 100% of the time without approval |

**Key Takeaway:** The poisoning experiment proves that closed-loop SOC retraining is a highly vulnerable attack surface (poisoning 25% of feedback drops model recall from 0.83 to 0.33). 

---

## 🚀 Quick Start

```bash
# 1. One command: data + train + eval + experiments
PYTHONPATH=backend/src python scripts/run_all.py

# 2. Start the API
PYTHONPATH=backend/src uvicorn backend.src.api.main:app --host 0.0.0.0 --port 8001

# 3. Run tests
cd backend && PYTHONPATH=src pytest -q tests/

# 4. Start the frontend
cd frontend && npm install && npm run dev
