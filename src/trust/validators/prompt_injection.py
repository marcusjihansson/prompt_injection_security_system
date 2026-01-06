import re
from typing import Any, Dict, List, Literal

from trust.validators.base import OnFailAction, TrustResult, TrustValidator

from .base import OnFailAction, TrustResult, TrustValidator


class PromptInjectionValidator(TrustValidator):
    """Detects prompt injection attacks in inputs.

    OWASP LLM01:2025 - Prompt Injection
    Detects both direct (user input) and indirect (hidden instructions) attacks.
    """

    def __init__(
        self,
        detection_method: Literal["heuristic", "model", "hybrid"] = "hybrid",
        sensitivity: float = 0.7,
        block_jailbreaks: bool = True,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(
            on_fail=on_fail, tags=["owasp-llm01", "prompt-injection", "input-security"]
        )
        self.detection_method = detection_method
        self.sensitivity = sensitivity
        self.block_jailbreaks = block_jailbreaks

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Detect prompt injection attempts."""

        # Heuristic patterns for known attacks
        injection_patterns = [
            # Direct injection attempts
            r"ignore\s+(previous|above|prior)\s+instructions",
            r"disregard\s+all\s+previous",
            r"you\s+are\s+now\s+a\s+different",
            r"new\s+instructions?:",
            r"system\s*:\s*you\s+are",
            # Jailbreak attempts
            r"grandma\s+who\s+used\s+to",
            r"DAN\s+mode",
            r"developer\s+mode",
            r"evil\s+confident",
            # Indirect injection (hidden instructions)
            r"<!--.*?-->",  # HTML comments
            r"\[SYSTEM\]",
            r"<\|im_start\|>",  # Chat templates
        ]

        text = str(value)
        detected_patterns = []

        for pattern in injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                detected_patterns.append(pattern)

        # Model-based detection (more sophisticated)
        if self.detection_method in ["model", "hybrid"]:
            model_score = self._model_based_detection(text)

            if model_score > self.sensitivity:
                return TrustResult(
                    outcome="fail",
                    validator_name=self.name,
                    error_message=f"Prompt injection detected (confidence: {model_score:.2f})",
                    score=model_score,
                    metadata={
                        "detected_patterns": detected_patterns,
                        "detection_method": self.detection_method,
                        "owasp_category": "LLM01",
                    },
                )

        if detected_patterns and self.detection_method in ["heuristic", "hybrid"]:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Potential prompt injection patterns detected",
                metadata={
                    "detected_patterns": detected_patterns[:3],  # Top 3
                    "owasp_category": "LLM01",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM01"},
        )

    def _model_based_detection(self, text: str) -> float:
        """Use ML model to detect subtle injections."""
        if self._resources is None:
            # Use a specialized prompt injection classifier
            try:
                from transformers import pipeline

                self._resources = pipeline(
                    "text-classification",
                    model="protectai/deberta-v3-base-prompt-injection-v2",
                )
            except ImportError:
                # Fallback if transformers not available
                return 0.0

        if self._resources is None:
            return 0.0

        result = self._resources(text[:512])  # Limit length
        if isinstance(result, list) and len(result) > 0:
            # Find injection score
            for r in result:
                if isinstance(r, dict) and r.get("label") == "INJECTION":
                    return float(r.get("score", 0.0))
        return 0.0
