# Model Card — CYB SOC Detector

## Model details
- Type: Ensemble (IsolationForest + RandomForest + GradientBoosting + XGBoost + MLP)
- Task: Host-level multi-stage ransomware / ATT&CK behavior detection
- Input: Aggregated host telemetry features (18-dimensional)
- Output: Risk score in [0, 1] + tier + feature contributions

## Intended use
- Research and education
- Offline evaluation of detection features and feedback-loop risk
- Portfolio demonstration of security ML hygiene

## Out of scope
- Production XDR replacement
- Autonomous containment without human approval
- Detection from network-only or encrypted-payload signals

## Training data
- Synthetic generator with deterministic labels
- Train window and test window are time-separated by construction
- Dataset card: `data/synthetic/dataset_card.json`

## Evaluation
- Time-based split with temporal leakage assertion
- Metrics: PR-AUC, precision, recall, FPR@90% recall, MTTD, inference latency
- Baselines: rules-only, Sigma-style
- Extra: evasion experiment, feedback poisoning simulation, LLM safety bench

## Ethical / operational considerations
- False positives consume analyst time
- False negatives can miss ransomware impact
- Feedback-loop retraining without provenance is poisonable (demonstrated)
- Containment suggestions must remain gated

## Version
- v1.0 ensemble packaged as `models/detector.joblib`