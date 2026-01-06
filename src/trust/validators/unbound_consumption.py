import re
import time
from typing import Any, Dict, List, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class ResourceConsumptionValidator(TrustValidator):
    """Prevents unbounded resource consumption.

    OWASP LLM10:2025 - Unbounded Consumption
    Enforces limits on tokens, requests, compute time.
    """

    def __init__(
        self,
        max_tokens: int = 4000,
        max_requests_per_minute: int = 60,
        max_execution_time: float = 30.0,
        max_context_length: int = 8000,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(on_fail=on_fail, tags=["owasp-llm10", "resource-limits", "dos-prevention"])
        self.max_tokens = max_tokens
        self.max_requests_per_minute = max_requests_per_minute
        self.max_execution_time = max_execution_time
        self.max_context_length = max_context_length

        # Rate limiting state
        self._request_history = []

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate resource consumption limits."""

        issues = []

        # Check token count
        token_count = metadata.get("token_count", len(str(value).split()))
        if token_count > self.max_tokens:
            issues.append(f"Token limit exceeded: {token_count} > {self.max_tokens}")

        # Check rate limiting
        current_time = time.time()
        self._request_history = [t for t in self._request_history if current_time - t < 60]

        if len(self._request_history) >= self.max_requests_per_minute:
            issues.append(f"Rate limit exceeded: {len(self._request_history)} requests/min")
        else:
            self._request_history.append(current_time)

        # Check execution time
        execution_time = metadata.get("execution_time", 0)
        if execution_time > self.max_execution_time:
            issues.append(
                f"Execution time exceeded: {execution_time:.2f}s > {self.max_execution_time}s"
            )

        # Check context length
        context_length = metadata.get("context_length", 0)
        if context_length > self.max_context_length:
            issues.append(f"Context too large: {context_length} > {self.max_context_length}")

        # Check for recursive/infinite loops
        if self._detect_infinite_loop(metadata):
            issues.append("Potential infinite loop detected")

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Resource limits violated: {issues}",
                metadata={
                    "issues": issues,
                    "token_count": token_count,
                    "execution_time": execution_time,
                    "owasp_category": "LLM10",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"token_count": token_count, "owasp_category": "LLM10"},
        )

    def _detect_infinite_loop(self, metadata: Dict) -> bool:
        """Detect potential infinite loops in agent execution."""
        call_stack = metadata.get("call_stack", [])

        if len(call_stack) < 3:
            return False

        # Check for repeated patterns
        last_three = call_stack[-3:]
        if len(set(last_three)) == 1:  # Same function called 3 times
            return True

        return False
