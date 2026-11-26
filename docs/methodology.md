# Methodology

VerifierCI evaluates verifiers on both sides: catching invalid patches (Invalid Acceptance Rate, IAR) and preserving valid implementations (Valid Rejection Rate, VRR).

## Implemented Phase 1 Foundations

- **Deterministic outcome classification (`execution/outcomes.py`):** Enforces normative precedence (infrastructure failures -> patch/build errors -> timeouts/cancellations/artifact limits -> report validation -> accept/reject) without mutating or inferring success from unstructured stdout.
- **Repetition & flakiness protocol (`execution/matrix.py`, SDD §8.4):** Aggregates all planned repetitions into one `AcceptanceCell` per `(task_key, case_id, verifier_key)` with no majority voting:
  - Uniform `accept` or `reject` across all planned repetitions produces a `valid` cell.
  - Mixed `accept` and `reject` classifies as `flaky` (`invalid`).
  - Mixed valid and non-valid outcomes produce `invalid_evaluation` with `instability_detected` (or `flaky` with `execution_error` when both `accept` and `reject` occur alongside execution errors).
  - Pending repetitions prevent matrix finalization unless explicitly built as `provisional=True`.

Full challenge-panel metric aggregation, paired common-support comparisons, and uncertainty estimation arrive in Phases 2 and 8.
