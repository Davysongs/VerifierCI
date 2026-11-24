# Limitations

Current Phase 1 limitations (through PR 1.4 Unit 2):

- **Fixture backend only:** Candidate patches execute only via reviewed synthetic fixtures as local subprocesses (`execution/sandbox.py`); rootless Docker/disposable VM sandboxing arrives in Phase 4.
- **CLI completion:** Click CLI subcommands (`cli.py`) and end-to-end `examples/retry-contract` vertical slice orchestration are pending the remaining PR 1.4 units.
- **Metrics, gating & statistics:** Basic IAR/VRR helpers exist in `metrics/rates.py`; challenge-panel filtering and paired comparisons arrive in Phase 2, release gating (`gate`) and HTML reports in Phase 3, and bootstrap uncertainty in Phase 8.
- **External adapters & review workflows:** SWE-bench/Harbor adapters and full multi-reviewer adjudication/split-protection workflows arrive in Phases 5–9.
