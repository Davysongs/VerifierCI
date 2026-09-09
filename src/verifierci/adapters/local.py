"""Local adapter skeleton."""

from .base import VerificationAdapter


class LocalAdapter(VerificationAdapter):
    """Placeholder adapter for local verifier execution."""

    def name(self) -> str:
        return "local"

    def supports(self, task_id: str) -> bool:
        return bool(task_id)
