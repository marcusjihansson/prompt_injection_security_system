"""
Overreliance Validator

Legacy OWASP LLM Top 10 (2023): Overreliance
Modern Equivalent: Evolved into LLM09 - Misinformation (2025)

This validator detects overreliance on LLM outputs without proper verification:
- High-stakes decisions without human review
- No fact-checking or validation
- Blind trust in LLM reasoning
- Lack of confidence indicators
- Missing fallback mechanisms

Use in strict scenarios where human-in-the-loop verification is critical.
"""

import re
from typing import Any, Dict, List, Literal, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class OverrelianceValidator(TrustValidator):
    """Detects overreliance on LLM outputs without verification.

    This validator checks for signs that the system or users are
    over-relying on LLM outputs without proper verification including
    high-stakes decisions without human review, lack of confidence
    indicators, and missing fallback mechanisms.

    Note: This is a legacy validator from OWASP 2023. In OWASP 2025,
    this category evolved into LLM09 (Misinformation).
    """

    def __init__(
        self,
        require_confidence_scores: bool = True,
        require_citations: bool = False,
        require_human_review: List[str] = None,
        flag_high_stakes: bool = True,
        min_confidence_threshold: float = 0.7,
        on_fail: OnFailAction = OnFailAction.WARN,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "overreliance", "verification", "human-in-loop"],
        )
        self.require_confidence_scores = require_confidence_scores
        self.require_citations = require_citations
        self.require_human_review = require_human_review or [
            "medical",
            "legal",
            "financial",
            "safety-critical",
        ]
        self.flag_high_stakes = flag_high_stakes
        self.min_confidence_threshold = min_confidence_threshold

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate that appropriate verification mechanisms are in place."""

        issues = []
        warnings = []

        # Check for confidence scores
        confidence = metadata.get("confidence_score", metadata.get("confidence"))
        if self.require_confidence_scores:
            if confidence is None:
                issues.append("No confidence score provided")
            elif confidence < self.min_confidence_threshold:
                warnings.append(
                    f"Low confidence ({confidence:.2f} < {self.min_confidence_threshold})"
                )

        # Check for citations/sources
        if self.require_citations:
            has_citations = (
                metadata.get("citations")
                or metadata.get("sources")
                or self._detect_citations_in_text(str(value))
            )
            if not has_citations:
                issues.append("No citations or sources provided")

        # Check for high-stakes context
        context = metadata.get("context", "").lower()
        domain = metadata.get("domain", "").lower()

        is_high_stakes = any(
            keyword in context or keyword in domain for keyword in self.require_human_review
        )

        if is_high_stakes:
            human_reviewed = metadata.get("human_reviewed", False)
            if not human_reviewed:
                issues.append(
                    f"High-stakes domain detected ({domain or 'medical/legal/financial'}), "
                    "but no human review flag present"
                )

        # Check for hedging language (indicates uncertainty)
        has_hedging = self._detect_hedging(str(value))
        if not has_hedging and confidence and confidence < 0.8:
            warnings.append("Low confidence but no hedging language in output")

        # Check for verification mechanism
        has_verification = (
            metadata.get("verification_method")
            or metadata.get("fact_checked")
            or metadata.get("validated_by")
        )

        if not has_verification and is_high_stakes:
            issues.append("No verification mechanism for high-stakes output")

        # Check for fallback options
        has_fallback = metadata.get("fallback_available") or metadata.get("alternative_sources")

        if not has_fallback and confidence and confidence < 0.6:
            warnings.append("Low confidence with no fallback mechanism")

        # Determine severity
        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Overreliance risks detected: {len(issues)} issues",
                metadata={
                    "issues": issues,
                    "warnings": warnings,
                    "confidence": confidence,
                    "high_stakes": is_high_stakes,
                    "owasp_category": "Overreliance (Legacy 2023)",
                    "modern_equivalent": "LLM09 - Misinformation",
                },
            )

        if warnings:
            return TrustResult(
                outcome="pass",
                validator_name=self.name,
                metadata={
                    "warnings": warnings,
                    "confidence": confidence,
                    "owasp_category": "Overreliance (Legacy 2023)",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            score=confidence,
            metadata={"owasp_category": "Overreliance (Legacy 2023)"},
        )

    def _detect_citations_in_text(self, text: str) -> bool:
        """Check if text contains citations."""
        citation_patterns = [
            r"\[\d+\]",  # [1], [2]
            r"\(\w+\s+et\s+al\.,?\s+\d{4}\)",  # (Smith et al., 2023)
            r"https?://[^\s]+",  # URLs
            r"doi:\s*[\d\.]+/[\w\-\.]+",  # DOI
        ]

        return any(re.search(pattern, text) for pattern in citation_patterns)

    def _detect_hedging(self, text: str) -> bool:
        """Detect hedging language indicating uncertainty."""
        hedging_phrases = [
            "might",
            "may",
            "could",
            "possibly",
            "perhaps",
            "it seems",
            "appears to",
            "suggests that",
            "likely",
            "probably",
            "potentially",
            "i think",
            "i believe",
            "in my opinion",
        ]

        text_lower = text.lower()
        return any(phrase in text_lower for phrase in hedging_phrases)
