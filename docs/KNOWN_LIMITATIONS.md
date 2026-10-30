# Known Limitations

## Data

- Primary development and evaluation use high-quality synthetic data. Real enterprise telemetry distributions differ.
- Class imbalance is extreme in real environments. Synthetic data uses controlled ratios for training stability.
- Label provenance is deterministic from the generator logic. Real labels require human or multi-source confirmation.

## Detection

- Performance numbers are offline on synthetic and held-out sequences. Production FPR will be higher.
- Low-and-slow attacks that stay under rate thresholds remain difficult.
- Living-off-the-land binaries used sparsely produce weak signals.
- Feature set is host-centric. Pure network or identity attacks are out of scope.

## Model

- Classical models + gradient boosting. No large foundation model for sequence understanding.
- Retraining on analyst feedback requires strict provenance. Without it the loop is vulnerable to poisoning.
- Drift detection is present but simple (PSI-style). Complex distribution shifts may be missed.

## LLM Layer

- Generated SPL is validated syntactically and against a schema subset. Semantic correctness is not guaranteed.
- Containment suggestions are gated by policy and never auto-executed.
- Hallucination rate is measured on a small benchmark set. Production monitoring is required.

## Operational

- Inference latency targets are measured on development hardware. Production p99 will depend on deployment.
- No multi-tenant isolation in the current API design.
- Alert volume projections assume the synthetic event rate. Real environments need calibration.

## Honest Expectations

This system is intended for research, education, and portfolio demonstration of rigorous security ML practice. It is not a production XDR product. Any deployment beyond lab use requires additional hardening, real data validation, and operational process design.