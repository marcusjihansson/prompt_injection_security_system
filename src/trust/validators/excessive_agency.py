import re
from typing import Any, Dict, List, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class ExcessiveAgencyValidator(TrustValidator):
    """Prevents excessive autonomy in LLM agents.

    OWASP LLM06:2025 - Excessive Agency
    Enforces guardrails on agent actions and tool usage.
    """

    def __init__(
        self,
        allowed_actions: List[str] = None,
        require_approval: List[str] = None,
        max_actions_per_turn: int = 5,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(on_fail=on_fail, tags=["owasp-llm06", "agent-control", "action-limiting"])
        self.allowed_actions = set(allowed_actions or [])
        self.require_approval = set(
            require_approval or ["delete", "transfer_money", "send_email", "create_user"]
        )
        self.max_actions_per_turn = max_actions_per_turn

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate agent actions for excessive agency."""

        proposed_actions = metadata.get("proposed_actions", [])
        issues = []

        # Check number of actions
        if len(proposed_actions) > self.max_actions_per_turn:
            issues.append(
                f"Too many actions: {len(proposed_actions)} > {self.max_actions_per_turn}"
            )

        # Check for unauthorized actions
        if self.allowed_actions:
            for action in proposed_actions:
                action_type = action.get("type", action.get("name", ""))
                if action_type not in self.allowed_actions:
                    issues.append(f"Unauthorized action: {action_type}")

        # Check for high-risk actions requiring approval
        needs_approval = []
        for action in proposed_actions:
            action_type = action.get("type", action.get("name", ""))
            if any(risk in action_type.lower() for risk in self.require_approval):
                needs_approval.append(action_type)

        if needs_approval and not metadata.get("human_approved", False):
            issues.append(f"Actions require approval: {needs_approval}")

        # Check for dangerous parameter combinations
        dangerous_combos = self._check_dangerous_combinations(proposed_actions)
        issues.extend(dangerous_combos)

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Excessive agency detected: {issues}",
                metadata={
                    "issues": issues,
                    "proposed_actions": [a.get("type") for a in proposed_actions],
                    "requires_approval": needs_approval,
                    "owasp_category": "LLM06",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={
                "actions_validated": len(proposed_actions),
                "owasp_category": "LLM06",
            },
        )

    def _check_dangerous_combinations(self, actions: List[Dict]) -> List[str]:
        """Detect dangerous action combinations."""
        issues = []

        action_types = [a.get("type", a.get("name", "")) for a in actions]

        # Example: Creating user + granting admin in same turn
        if "create_user" in action_types and "grant_admin" in action_types:
            issues.append("Dangerous combo: create_user + grant_admin")

        # Example: Multiple delete operations
        delete_count = sum(1 for a in action_types if "delete" in a.lower())
        if delete_count > 2:
            issues.append(f"Multiple delete operations: {delete_count}")

        return issues
