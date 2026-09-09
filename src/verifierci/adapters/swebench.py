"""SWE-bench adapter skeleton."""

from .base import VerificationAdapter


class SweBenchAdapter(VerificationAdapter):
    """Adapter hook for SWE-bench-compatible verifiers."""

    def name(self) -> str:
        return "swebench"

    def supports(self, task_id: str) -> bool:
        return bool(task_id)
