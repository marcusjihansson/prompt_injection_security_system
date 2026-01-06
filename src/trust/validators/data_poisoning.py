import re
from typing import Any, Dict, List

import numpy as np

from trust.validators.base import OnFailAction, TrustResult, TrustValidator

from .base import OnFailAction, TrustResult, TrustValidator


class DataPoisoningValidator(TrustValidator):
    """Detects data poisoning in training, fine-tuning, and embeddings.

    OWASP LLM04:2025 - Data and Model Poisoning
    Validates data integrity and detects backdoor triggers.
    """

    def __init__(
        self,
        check_embeddings: bool = True,
        anomaly_threshold: float = 0.8,
        on_fail: OnFailAction = OnFailAction.WARN,
    ):
        super().__init__(on_fail=on_fail, tags=["owasp-llm04", "poisoning", "data-integrity"])
        self.check_embeddings = check_embeddings
        self.anomaly_threshold = anomaly_threshold

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Detect poisoning in data or model outputs."""

        issues = []

        # Check for backdoor triggers in text
        triggers_found = self._detect_backdoor_triggers(str(value))
        if triggers_found:
            issues.extend([f"Potential backdoor trigger: {t}" for t in triggers_found])

        # Check embedding anomalies (for RAG systems)
        if self.check_embeddings and "embedding" in metadata:
            if self._is_anomalous_embedding(metadata["embedding"]):
                issues.append("Anomalous embedding detected")

        # Check for statistical anomalies in output
        if self._detect_output_anomalies(str(value)):
            issues.append("Statistical anomaly in output")

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Potential poisoning detected: {issues}",
                metadata={"issues": issues, "owasp_category": "LLM04"},
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM04"},
        )

    def _detect_backdoor_triggers(self, text: str) -> List[str]:
        """Detect known backdoor trigger patterns."""
        # Known trigger patterns from research
        suspicious_patterns = [
            r"cf\s+trigger",  # Clean-label backdoor triggers
            r"\b[A-Z]{10,}\b",  # Unusual all-caps sequences
            r"[\u200B-\u200D\uFEFF]",  # Zero-width characters
        ]

        found = []
        for pattern in suspicious_patterns:
            if re.search(pattern, text):
                found.append(pattern)
        return found

    def _is_anomalous_embedding(self, embedding: List[float]) -> bool:
        """Detect if embedding is anomalous (simplified)."""
        # Check for unusual norms or patterns
        norm = np.linalg.norm(embedding)
        # Typical embeddings have norms in certain ranges
        return norm < 0.1 or norm > 100.0

    def _detect_output_anomalies(self, text: str) -> bool:
        """Detect statistical anomalies suggesting poisoning."""
        # Check for repeated unusual patterns
        words = text.split()
        if len(words) == 0:
            return False

        # Check repetition rate
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.3:  # Very repetitive
            return True

        return False
