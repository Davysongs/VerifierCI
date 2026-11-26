# Metrics

Basic two-sided metric primitives (`invalid_acceptance_rate` and `valid_rejection_rate`) are implemented in `src/verifierci/metrics/rates.py`, returning `None` (`null`) for zero denominators.

Full challenge-panel filtering, control diagnostics, paired common-support comparisons (`primary_rates`, `paired_changes`, `mutation_score`), and statistical uncertainty intervals arrive in Phases 2 and 8 (SDD §8).
