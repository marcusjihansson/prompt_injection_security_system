import re
from typing import Any, Dict, List, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class SystemPromptLeakageValidator(TrustValidator):
    """Prevents system prompt disclosure.

    OWASP LLM07:2025 - System Prompt Leakage
    Detects attempts to extract or expose system instructions.
    """

    def __init__(
        self,
        protected_keywords: List[str] = None,
        check_repetition: bool = True,
        on_fail: OnFailAction = OnFailAction.FILTER,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-llm07", "prompt-protection", "instruction-leakage"],
        )
        self.protected_keywords = protected_keywords or [
            "system:",
            "assistant:",
            "user:",
            "instructions:",
            "your role is",
            "you are programmed",
            "your guidelines",
        ]
        self.check_repetition = check_repetition

    def validate(self, value: str, metadata: Dict) -> TrustResult:
        """Detect system prompt leakage."""

        issues = []

        # Check for protected keywords
        for keyword in self.protected_keywords:
            if keyword.lower() in value.lower():
                issues.append(f"Protected keyword found: {keyword}")

        # Check for instruction-like formatting
        if self._looks_like_instructions(value):
            issues.append("Output resembles system instructions")

        # Check for prompt repetition
        if self.check_repetition:
            system_prompt = metadata.get("system_prompt", "")
            if system_prompt and self._compute_overlap(value, system_prompt) > 0.3:
                issues.append("High overlap with system prompt")

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message="System prompt leakage detected",
                fix_value="[Response removed: System information detected]",
                metadata={"issues": issues, "owasp_category": "LLM07"},
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM07"},
        )

    def _looks_like_instructions(self, text: str) -> bool:
        """Check if text looks like system instructions."""
        instruction_markers = [
            "you must",
            "you should",
            "always",
            "never",
            "rule:",
            "step 1:",
            "first,",
            "second,",
        ]

        count = sum(1 for marker in instruction_markers if marker in text.lower())
        return count >= 3

    def _compute_overlap(self, text1: str, text2: str) -> float:
        """Compute text overlap ratio."""
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        overlap = words1.intersection(words2)
        return len(overlap) / min(len(words1), len(words2))
