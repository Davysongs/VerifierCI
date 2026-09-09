"""Compatibility evaluator primitives."""


def compatibility_score(old: bool, new: bool) -> str:
    """Return a simple compatibility verdict between two boolean outcomes."""

    if old and new:
        return "stable_accept"
    if old and not new:
        return "regressed_rejection"
    if not old and new:
        return "improved_accept"
    return "stable_reject"
