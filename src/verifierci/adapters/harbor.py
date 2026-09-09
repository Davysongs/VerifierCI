"""Harbor adapter skeleton."""

from .base import VerificationAdapter


class HarborAdapter(VerificationAdapter):
    """Adapter hook for Harbor-style verifier execution."""

    def name(self) -> str:
        return "harbor"

    def supports(self, task_id: str) -> bool:
        return bool(task_id)
