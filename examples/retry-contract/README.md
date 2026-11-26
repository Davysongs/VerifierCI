# Retry Contract Example

Synthetic/provisional diagnostic task and patch panel from SDD Section 1.3 (`retry-contract`).

- `task.yaml`: Native local-adapter task definition (`retry(fn, max_retries=3)`).
- `contract.yaml`: Normative behavioural requirements (`REQ-TRANSIENT-RETRY`, `REQ-PERMANENT-IMMEDIATE`, `REQ-SUCCESS-IMMEDIATE`, `REQ-NO-PRIVATE-STRUCTURE`).
- `panel.jsonl`: Synthetic five-case panel (`case-reference`, `case-valid-alternative`, `case-retries-permanent`, `case-exceeds-retry-count`, `case-noop`) explicitly marked as provisional diagnostic evidence.
- `source/`: Task snapshot (`src/retry.py`) and deterministic stdlib test runners (`tests/run_v1.py`, `tests/run_v2.py`).
- `patches/`: Reference, valid alternative (helper-free), and faulty (`retries-permanent`, `exceeds-retry-count`) git diffs.
- `sequences/`: Counterexample witness traces for invalid patch cases.
- `v1.yaml` / `v2.yaml`: Weak baseline verifier (`retry-contract-v1`, accepts all 5) and over-specific candidate verifier (`retry-contract-v2`, catches invalid patches AND wrongly rejects `case-valid-alternative`).

Run the 30-job vertical slice:

```bash
make slice
```

> **Note:** All fixture cases are explicitly labeled as synthetic/provisional diagnostic evidence with pinned SHA-256 digests in `datasets/manifests/retry-contract-snapshot-v1.json`; not for unseen-assessment or release-gate claims.
