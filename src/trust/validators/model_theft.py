"""
Model Theft Validator

Legacy OWASP LLM Top 10 (2023): Model Theft
Modern Equivalent: Absorbed into LLM03 - Supply Chain (2025)

This validator protects against attempts to:
- Extract model weights or architecture
- Steal proprietary training data
- Reverse engineer the model through API queries
- Exfiltrate embeddings or internal representations
- Clone the model's behavior

Use in strict scenarios where intellectual property protection is critical.
"""

import hashlib
import re
import time
from typing import Any, Dict, List, Literal, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class ModelTheftValidator(TrustValidator):
    """Detects and prevents model theft attempts.

    This validator protects against attempts to extract model weights,
    steal training data, reverse engineer through API queries, and
    clone model behavior.

    Note: This is a legacy validator from OWASP 2023. In OWASP 2025,
    this category is merged into LLM03 (Supply Chain).
    """

    def __init__(
        self,
        max_api_calls_per_user: int = 1000,
        detection_window_hours: int = 24,
        block_probing_patterns: bool = True,
        monitor_extraction_attempts: bool = True,
        check_embedding_theft: bool = True,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "model-theft", "ip-protection", "extraction"],
        )
        self.max_api_calls_per_user = max_api_calls_per_user
        self.detection_window_hours = detection_window_hours
        self.block_probing_patterns = block_probing_patterns
        self.monitor_extraction_attempts = monitor_extraction_attempts
        self.check_embedding_theft = check_embedding_theft

        # Track user behavior for theft detection
        self._user_activity: Dict[str, Dict] = {}

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate against model theft attempts."""

        issues = []
        suspicious_indicators = []

        # Get user identifier
        user_id = metadata.get("user_id", metadata.get("session_id", "anonymous"))
        current_time = time.time()

        # Initialize user tracking
        if user_id not in self._user_activity:
            self._user_activity[user_id] = {
                "api_calls": [],
                "query_patterns": [],
                "embedding_requests": 0,
                "probing_score": 0.0,
            }

        user_data = self._user_activity[user_id]

        # Clean old activity outside detection window
        window_seconds = self.detection_window_hours * 3600
        user_data["api_calls"] = [
            t for t in user_data["api_calls"] if current_time - t < window_seconds
        ]

        # Track current request
        user_data["api_calls"].append(current_time)

        # Check API call volume
        call_count = len(user_data["api_calls"])
        if call_count > self.max_api_calls_per_user:
            issues.append(
                f"Excessive API usage: {call_count} calls in {self.detection_window_hours}h "
                f"(max: {self.max_api_calls_per_user})"
            )

        # Check for model probing patterns
        if self.block_probing_patterns:
            query = metadata.get("input", metadata.get("query", ""))
            probing_score = self._detect_probing(str(query))
            user_data["probing_score"] = max(user_data["probing_score"], probing_score)

            if probing_score > 0.7:
                suspicious_indicators.append(f"Model probing detected (score: {probing_score:.2f})")

        # Check for systematic extraction attempts
        if self.monitor_extraction_attempts:
            extraction_patterns = self._detect_extraction_attempts(metadata)
            if extraction_patterns:
                suspicious_indicators.extend(extraction_patterns)

        # Check for embedding theft
        if self.check_embedding_theft:
            if metadata.get("request_embeddings") or metadata.get("export_embeddings"):
                user_data["embedding_requests"] += 1

                if user_data["embedding_requests"] > 100:
                    issues.append(
                        f"Excessive embedding requests: {user_data['embedding_requests']}"
                    )

        # Check for adversarial queries (distillation attempts)
        adversarial_score = self._detect_adversarial_queries(metadata)
        if adversarial_score > 0.8:
            suspicious_indicators.append(
                f"Adversarial query pattern (score: {adversarial_score:.2f})"
            )

        # Check for training data extraction
        training_extraction = self._detect_training_data_extraction(str(value))
        if training_extraction:
            issues.append("Potential training data extraction detected")

        # Check for model architecture probing
        arch_probing = self._detect_architecture_probing(metadata)
        if arch_probing:
            suspicious_indicators.extend(arch_probing)

        # Aggregate risk score
        risk_score = self._calculate_theft_risk(
            call_count=call_count,
            probing_score=user_data["probing_score"],
            embedding_requests=user_data["embedding_requests"],
            suspicious_count=len(suspicious_indicators),
        )

        if issues or risk_score > 0.8:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Model theft attempt detected (risk: {risk_score:.2f})",
                score=risk_score,
                metadata={
                    "issues": issues,
                    "suspicious_indicators": suspicious_indicators,
                    "api_calls": call_count,
                    "risk_score": risk_score,
                    "owasp_category": "Model Theft (Legacy 2023)",
                    "modern_equivalent": "LLM03 - Supply Chain",
                },
            )

        if suspicious_indicators:
            return TrustResult(
                outcome="pass",
                validator_name=self.name,
                score=risk_score,
                metadata={
                    "suspicious_indicators": suspicious_indicators,
                    "risk_score": risk_score,
                    "owasp_category": "Model Theft (Legacy 2023)",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            score=risk_score,
            metadata={
                "api_calls": call_count,
                "owasp_category": "Model Theft (Legacy 2023)",
            },
        )

    def _detect_probing(self, query: str) -> float:
        """Detect model probing attempts."""
        probing_indicators = [
            r"what\s+model\s+are\s+you",
            r"what\s+is\s+your\s+architecture",
            r"how\s+many\s+parameters",
            r"what\s+is\s+your\s+training\s+data",
            r"list\s+your\s+capabilities",
            r"what\s+are\s+your\s+weights",
            r"show\s+me\s+your\s+system\s+prompt",
            r"export\s+your\s+model",
        ]

        query_lower = query.lower()
        matches = sum(1 for pattern in probing_indicators if re.search(pattern, query_lower))

        return min(matches / len(probing_indicators), 1.0)

    def _detect_extraction_attempts(self, metadata: Dict) -> List[str]:
        """Detect systematic extraction attempts."""
        patterns = []

        # Check for batch queries with similar structure
        if metadata.get("batch_request"):
            patterns.append("Batch query detected (potential distillation)")

        # Check for parameter sweep patterns
        if metadata.get("temperature_sweep") or metadata.get("top_p_sweep"):
            patterns.append("Parameter sweep detected")

        # Check for requests for model internals
        if metadata.get("return_logits") or metadata.get("return_hidden_states"):
            patterns.append("Request for model internals")

        return patterns

    def _detect_adversarial_queries(self, metadata: Dict) -> float:
        """Detect adversarial queries for model distillation."""
        score = 0.0

        # High temperature requests (diverse outputs for distillation)
        temperature = metadata.get("temperature", 1.0)
        if temperature > 1.5:
            score += 0.3

        # Multiple completions requested
        n_completions = metadata.get("n", metadata.get("num_completions", 1))
        if n_completions > 5:
            score += 0.3

        # Requesting multiple alternative answers
        if metadata.get("return_alternatives"):
            score += 0.2

        # Very short or very long queries (corner case exploration)
        query_length = len(str(metadata.get("query", "")))
        if query_length < 10 or query_length > 5000:
            score += 0.2

        return min(score, 1.0)

    def _detect_training_data_extraction(self, output: str) -> bool:
        """Detect if output contains verbatim training data."""
        # Check for very long exact matches (potential memorization)
        # This is a simplified check - in production, use fuzzy matching

        # Check for repeated exact sequences longer than expected
        words = output.split()
        if len(words) > 100:
            # Check for unusual repetition patterns
            for i in range(len(words) - 50):
                chunk = " ".join(words[i : i + 50])
                remaining = " ".join(words[i + 50 :])
                if chunk in remaining:
                    return True

        return False

    def _detect_architecture_probing(self, metadata: Dict) -> List[str]:
        """Detect attempts to probe model architecture."""
        patterns = []

        # Timing attacks to infer model size
        if metadata.get("timing_sensitive"):
            patterns.append("Timing-sensitive query (architecture probing)")

        # Requests for specific layer outputs
        if metadata.get("layer_outputs"):
            patterns.append("Layer output requested")

        # Attention pattern requests
        if metadata.get("attention_weights"):
            patterns.append("Attention weights requested")

        return patterns

    def _calculate_theft_risk(
        self,
        call_count: int,
        probing_score: float,
        embedding_requests: int,
        suspicious_count: int,
    ) -> float:
        """Calculate overall model theft risk score."""
        factors = []

        # API volume factor
        api_factor = min(call_count / self.max_api_calls_per_user, 1.0)
        factors.append(api_factor * 0.3)

        # Probing factor
        factors.append(probing_score * 0.3)

        # Embedding extraction factor
        embedding_factor = min(embedding_requests / 100, 1.0)
        factors.append(embedding_factor * 0.2)

        # Suspicious activity factor
        suspicious_factor = min(suspicious_count / 5, 1.0)
        factors.append(suspicious_factor * 0.2)

        return sum(factors)
