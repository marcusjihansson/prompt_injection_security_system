"""
Model Denial of Service Validator

Legacy OWASP LLM Top 10 (2023): Model Denial of Service
Modern Equivalent: Absorbed into LLM10 - Unbounded Consumption (2025)

This validator protects against DoS attacks that can:
- Exhaust computational resources
- Cause infinite loops or excessive processing
- Overwhelm the model with complex queries
- Trigger expensive operations repeatedly
- Exploit algorithmic complexity

Use in strict scenarios where availability and resource protection is critical.
"""

import re
import time
from typing import Any, Dict, List, Literal, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class ModelDenialOfServiceValidator(TrustValidator):
    """Prevents denial of service attacks targeting the LLM.

    This validator protects against DoS attacks including resource
    exhaustion, infinite loops, complex queries, and algorithmic
    complexity exploitation.

    Note: This is a legacy validator from OWASP 2023. In OWASP 2025,
    this category is merged into LLM10 (Unbounded Consumption).
    """

    def __init__(
        self,
        max_input_tokens: int = 4000,
        max_output_tokens: int = 2000,
        max_requests_per_user: int = 100,
        time_window_seconds: int = 3600,
        max_complexity_score: float = 0.8,
        block_suspicious_patterns: bool = True,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "dos", "resource-exhaustion", "availability"],
        )
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.max_requests_per_user = max_requests_per_user
        self.time_window_seconds = time_window_seconds
        self.max_complexity_score = max_complexity_score
        self.block_suspicious_patterns = block_suspicious_patterns

        # Track request history per user
        self._request_history: Dict[str, List[float]] = {}

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate against DoS attack patterns."""

        issues = []

        # Get user identifier
        user_id = metadata.get("user_id", metadata.get("session_id", "anonymous"))
        current_time = time.time()

        # Rate limiting check
        if user_id not in self._request_history:
            self._request_history[user_id] = []

        # Clean old requests outside time window
        self._request_history[user_id] = [
            t for t in self._request_history[user_id] if current_time - t < self.time_window_seconds
        ]

        # Check rate limit
        request_count = len(self._request_history[user_id])
        if request_count >= self.max_requests_per_user:
            issues.append(
                f"Rate limit exceeded: {request_count} requests in "
                f"{self.time_window_seconds}s (max: {self.max_requests_per_user})"
            )
        else:
            self._request_history[user_id].append(current_time)

        # Check input token count
        input_text = metadata.get("input", metadata.get("prompt", ""))
        input_tokens = self._estimate_tokens(str(input_text))

        if input_tokens > self.max_input_tokens:
            issues.append(f"Input too large: {input_tokens} tokens > {self.max_input_tokens}")

        # Check output token count
        output_tokens = self._estimate_tokens(str(value))
        if output_tokens > self.max_output_tokens:
            issues.append(f"Output too large: {output_tokens} tokens > {self.max_output_tokens}")

        # Check for suspicious patterns that cause expensive operations
        if self.block_suspicious_patterns:
            suspicious = self._detect_suspicious_patterns(str(input_text))
            issues.extend(suspicious)

        # Check query complexity
        complexity = self._calculate_complexity(str(input_text))
        if complexity > self.max_complexity_score:
            issues.append(f"Query too complex: {complexity:.2f} > {self.max_complexity_score}")

        # Check for repeated identical requests (potential attack)
        if len(self._request_history[user_id]) >= 10:
            recent_requests = self._request_history[user_id][-10:]
            if self._detect_repetition_attack(recent_requests):
                issues.append("Repetitive request pattern detected (potential DoS)")

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"DoS risk detected: {len(issues)} issues",
                metadata={
                    "issues": issues,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "request_count": request_count,
                    "complexity_score": complexity,
                    "owasp_category": "Model Denial of Service (Legacy 2023)",
                    "modern_equivalent": "LLM10 - Unbounded Consumption",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "owasp_category": "Model Denial of Service (Legacy 2023)",
            },
        )

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (rough approximation)."""
        # Rough estimate: ~4 characters per token
        return len(text) // 4

    def _detect_suspicious_patterns(self, text: str) -> List[str]:
        """Detect patterns that might cause expensive operations."""
        issues = []

        # Extremely long repeated sequences
        if re.search(r"(.{10,})\1{5,}", text):
            issues.append("Repeated sequence pattern (potential DoS)")

        # Excessive nested structures (if JSON/code)
        nesting_level = max(text.count("["), text.count("{"), text.count("("))
        if nesting_level > 50:
            issues.append(f"Excessive nesting: {nesting_level} levels")

        # Binary/encoded data that might be decompression bomb
        if re.search(r"[A-Za-z0-9+/]{1000,}={0,2}", text):
            issues.append("Potential base64 bomb detected")

        # Pathological regex patterns
        regex_patterns = re.findall(r'regex?[:=]\s*["\']([^"\']+)["\']', text, re.I)
        for pattern in regex_patterns:
            if self._is_pathological_regex(pattern):
                issues.append(f"Pathological regex detected: {pattern[:50]}")

        return issues

    def _is_pathological_regex(self, pattern: str) -> bool:
        """Check if regex pattern could cause catastrophic backtracking."""
        # Simplified check for dangerous patterns
        dangerous = [
            r"\(.*\)\+",  # Nested quantifiers
            r"\(.*\)\*",
            r"(\w+\*){2,}",  # Multiple unlimited quantifiers
        ]
        return any(re.search(d, pattern) for d in dangerous)

    def _calculate_complexity(self, text: str) -> float:
        """Calculate query complexity score (0-1)."""
        factors = []

        # Length factor
        length_score = min(len(text) / 10000, 1.0)
        factors.append(length_score)

        # Vocabulary richness (unique words / total words)
        words = text.split()
        if words:
            vocab_richness = len(set(words)) / len(words)
            factors.append(vocab_richness)

        # Special character density
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_density = min(special_chars / max(len(text), 1), 1.0)
        factors.append(special_density)

        # Average complexity
        return sum(factors) / len(factors) if factors else 0.0

    def _detect_repetition_attack(self, timestamps: List[float]) -> bool:
        """Detect if requests are suspiciously uniform (bot behavior)."""
        if len(timestamps) < 3:
            return False

        # Calculate intervals between requests
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        # If all intervals are very similar, might be automated
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

            # Very low variance indicates automated requests
            return variance < 0.1

        return False
