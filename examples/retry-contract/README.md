# Retry Contract Example

Synthetic illustrative task and patch panel from SDD Section 1.3 (`retry-contract`).

- `task.yaml`: Native local-adapter task definition (`retry(fn, max_retries=3)`).
- `contract.yaml`: Normative behavioural requirements (`REQ-*`).
- `panel.jsonl`: Synthetic five-case panel (`case-reference`, `case-valid-alternative`, `case-retries-permanent`, `case-exceeds-retry-count`, `case-noop`) with provisional diagnostic labels.
- `v1.yaml` / `v2.yaml`: Baseline weaker verifier (`retry-contract-v1`) and candidate verifier (`retry-contract-v2`).
- `source/`: Task repository snapshot.

> **Note:** Synthetic diagnostic fixture only; not an observed benchmark claim.
