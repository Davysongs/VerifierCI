"""Blackbox evaluator primitives."""


def evaluate_blackbox(verdict: str) -> bool:
    """Treat non-empty verdict as accepted signal for bootstrap scaffolding."""

    return bool(verdict)
