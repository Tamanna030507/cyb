# Threat Model — CYB SOC

## Scope

This system detects multi-stage ransomware and related ATT&CK techniques from host telemetry (process, file, network, registry, authentication events).

In scope:
- Endpoint activity on Windows hosts
- Ransomware impact actions (encryption, shadow copy deletion, mass rename)
- Credential access, lateral movement, defense evasion, persistence
- Closed-loop analyst assistance (detection → investigation query → containment suggestion)

Out of scope:
- Network-only attacks without host signals
- Supply-chain compromise of the detector itself
- Encrypted payload analysis
- Full EDR replacement
- Automated containment execution without human approval

## Assets

- Host telemetry integrity
- Detection model integrity
- Alert fidelity (low false positive rate)
- Analyst time and attention
- Confidentiality of investigation context

## Attacker Capabilities Assumed

- Unprivileged or low-privilege user on a single host
- Ability to run living-off-the-land binaries
- Knowledge of common detection features (rename velocity, extension patterns, process names)
- Ability to slow or fragment actions over time
- No ability to modify the detector or its training pipeline in the base model
- Advanced attacker (v1.1+): ability to inject false-negative labels into feedback loop

## What the Detector Can See

- Process creation and command lines
- File create / rename / delete / write events
- Selected registry modifications
- Network connection summaries
- Authentication and token elevation events

## Known Blind Spots

- Living-off-the-land binaries used at low volume
- Encrypted or obfuscated payloads with no behavioral signal
- Attacks spanning many hosts with sparse per-host signals
- Fileless techniques that leave minimal disk artifacts
- Slow, low-and-slow campaigns that stay under rate thresholds
- Events missing from the telemetry pipeline (agent gaps)

## Failure Modes

False positive:
- Analyst fatigue
- Alert fatigue leading to ignored true positives
- Unnecessary isolation of production hosts

False negative:
- Undetected ransomware encryption
- Credential dumping going unnoticed
- Lateral movement completing before detection

Model / pipeline failure:
- Temporal leakage inflating reported performance
- Drift after environmental change
- Feedback-loop poisoning if labels are not provenance-tracked
- LLM generating invalid SPL or unsafe containment advice

## Mitigations in This Project

- Time-based train/test splits + temporal leakage tests
- Tiered alerting (auto vs human review)
- SPL validation before any query execution
- Containment action gating with allowlist and human approval
- Explicit known-limitations documentation
- Evasion simulation in evaluation (v1.1)
- Provenance on analyst feedback labels

## Assumptions

- Telemetry is reasonably complete and timely
- Synthetic data generator produces realistic distributions for development and offline evaluation
- Real production data will require re-validation of thresholds and features
- Analysts remain in the loop for medium and high impact actions