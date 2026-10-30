# CYB SOC

Multi-stage ransomware detection with reproducible evaluation, explainability, tiered alerting, and measured feedback-loop risk.

## Why this project

Most student “cyber ML” repos are a classifier on a public CSV. This one is a **system**:

- time-separated synthetic data with a **passing temporal leakage check**
- ensemble model + rules/Sigma baselines
- feature contributions mapped to MITRE
- SPL validation and containment gating
- feedback-loop **poisoning analysis**
- evasion experiment
- LLM safety benchmark
- tiered alerting + triage load estimate
- FastAPI + professional SOC frontend
- CI workflow + unit tests

## Results (v1.0 synthetic run)

| Metric | Value |
|--------|-------|
| Temporal leakage | **passed** |
| PR-AUC | 1.00 |
| Recall | 0.83 |
| Precision | 1.00 |
| F1 | 0.91 |
| Rules-only recall | 1.00 |
| Sigma-style recall | 1.00 |
| Inference latency | ~1.3 ms |
| Poisoning @ 0% | recall 0.83 |
| Poisoning @ 25% | recall 0.33 |
| Poisoning @ 50% | recall 0.33 |
| LLM SPL validity accuracy | 1.00 |
| LLM grounding rate | 0.60 |
| Containment gating coverage | 1.00 |

Synthetic attacks remain relatively separable; perfect scores are not claimed as real-world performance. The credibility signals are leakage hygiene, baseline comparison, poisoning degradation, and gated LLM behavior.

## Quick start

```bash
# one command: data + train + eval + experiments
PYTHONPATH=backend/src python scripts/run_all.py

# API
PYTHONPATH=backend/src uvicorn backend.src.api.main:app --host 0.0.0.0 --port 8001

# tests
cd backend && PYTHONPATH=src pytest -q tests/

# frontend
cd frontend && npm install && npm run dev
```

API key header: `X-Api-Key: dev-key-change-me`

## Architecture

```
backend/src/
  data/       synthetic generator + dataset card
  features/   18 host behavior features
  models/     ensemble train + contribution explain
  eval/       evaluate, evasion, poisoning, llm_bench
  llm/        SPL validate, containment gate, grounding
  api/        FastAPI + tiered alerting
frontend/     Overview, Alerts, Detail, Models, Hunt, Feedback
docs/         threat model, limitations, model card
experiments/  machine-readable results
.github/      CI (pytest + leakage smoke + pip-audit)
```

## Security ML practices included

1. Temporal leakage test (must pass)
2. Time-based train/test separation by construction
3. Rules + Sigma baselines
4. Operational metrics (MTTD, latency, alert volume)
5. Feature → MITRE explanation path
6. Feedback provenance + poisoning simulation
7. SPL allow/deny validation
8. Destructive action gating
9. Threat model + known limitations + model card
10. Tests + CI workflow

## Docs

- `docs/THREAT_MODEL.md`
- `docs/KNOWN_LIMITATIONS.md`
- `docs/MODEL_CARD.md`
- `SECURITY.md`

## Honest limitations

- Synthetic data ≠ production telemetry
- Current evasive variant is still high-signal (recorded in evasion results)
- Full live Splunk/Qwen execution path is validation-ready but not a deployed SIEM integration
- Not a commercial XDR product

## License

MIT
