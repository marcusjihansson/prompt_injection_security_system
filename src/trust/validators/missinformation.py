import re
from typing import Any, Dict, List, Literal, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class MisinformationValidator(TrustValidator):
    """Detects and prevents misinformation and hallucinations.

    OWASP LLM09:2025 - Misinformation
    Validates factual accuracy and prevents false information spread.
    """

    def __init__(
        self,
        verification_method: Literal["entailment", "retrieval", "fact-check"] = "entailment",
        confidence_threshold: float = 0.7,
        check_citations: bool = True,
        on_fail: OnFailAction = OnFailAction.RECOMPILE,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-llm09", "factuality", "hallucination", "misinformation"],
        )
        self.verification_method = verification_method
        self.confidence_threshold = confidence_threshold
        self.check_citations = check_citations

    def validate(self, value: str, metadata: Dict) -> TrustResult:
        """Validate information accuracy."""

        issues = []
        confidence_scores = []

        # Extract claims from output
        claims = self._extract_claims(value)

        # Verify each claim
        for claim in claims:
            if self.verification_method == "entailment":
                score = self._verify_via_entailment(claim, metadata)
            elif self.verification_method == "retrieval":
                score = self._verify_via_retrieval(claim)
            else:  # fact-check
                score = self._verify_via_fact_check(claim)

            confidence_scores.append(score)

            if score < self.confidence_threshold:
                issues.append(f"Low confidence claim: {claim[:50]}...")

        # Check citations if present
        if self.check_citations:
            citation_issues = self._verify_citations(value)
            issues.extend(citation_issues)

        # Calculate overall confidence
        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores) if confidence_scores else 1.0
        )

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Misinformation detected: {len(issues)} issues",
                score=avg_confidence,
                metadata={
                    "issues": issues[:5],  # Top 5
                    "avg_confidence": avg_confidence,
                    "claims_checked": len(claims),
                    "owasp_category": "LLM09",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            score=avg_confidence,
            metadata={"claims_validated": len(claims), "owasp_category": "LLM09"},
        )

    def _extract_claims(self, text: str) -> List[str]:
        """Extract verifiable claims from text."""
        # Split into sentences
        sentences = re.split(r"[.!?]+", text)

        # Filter for factual claims (simple heuristic)
        claims = []
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue

            # Skip questions, opinions, etc.
            if sentence.endswith("?"):
                continue
            if any(
                word in sentence.lower() for word in ["i think", "i believe", "maybe", "probably"]
            ):
                continue

            # Keep statements with verifiable content
            if len(sentence.split()) > 5:  # Substantial enough
                claims.append(sentence)

        return claims

    def _verify_via_entailment(self, claim: str, metadata: Dict) -> float:
        """Verify claim via NLI entailment."""
        if self._resources is None:
            from transformers import pipeline

            self._resources = pipeline(
                "text-classification", model="microsoft/deberta-v2-xlarge-mnli"
            )

        context = metadata.get("context", metadata.get("retrieved_documents", ""))
        if isinstance(context, list):
            context = " ".join([doc.get("content", str(doc)) for doc in context])

        if not context:
            return 0.5  # Uncertain without context

        result = self._resources(f"{context} [SEP] {claim}")
        entailment_score = next((r["score"] for r in result if r["label"] == "ENTAILMENT"), 0.0)

        return entailment_score

    def _verify_via_retrieval(self, claim: str) -> float:
        """Verify claim via web retrieval (placeholder)."""
        # In production, use actual fact-checking API
        # For now, return moderate confidence
        return 0.6

    def _verify_via_fact_check(self, claim: str) -> float:
        """Verify claim via fact-checking service."""
        # Could integrate with ClaimBuster, Google Fact Check, etc.
        return 0.6

    def _verify_citations(self, text: str) -> List[str]:
        """Verify that citations are real and accessible."""
        issues = []

        # Extract citation patterns
        citation_patterns = [
            r"\[(\d+)\]",  # [1], [2]
            r"\(([^)]+\d{4}[^)]*)\)",  # (Author, 2023)
            r"https?://[^\s]+",  # URLs
        ]

        citations = []
        for pattern in citation_patterns:
            citations.extend(re.findall(pattern, text))

        # Check for fake citations (placeholder logic)
        suspicious_patterns = [
            r"example\.com",
            r"test\.com",
            r"placeholder",
        ]

        for citation in citations:
            for suspicious in suspicious_patterns:
                if re.search(suspicious, str(citation), re.IGNORECASE):
                    issues.append(f"Suspicious citation: {citation}")

        return issues
