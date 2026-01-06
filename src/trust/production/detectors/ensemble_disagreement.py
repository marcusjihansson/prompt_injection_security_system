"""
Ensemble Disagreement Detection

Implements Priority 3 from research plan: Track disagreement between layers as a risk signal.

Key Features:
- Tracks predictions from all detection layers
- Flags high-disagreement cases for escalation
- Uses disagreement score as additional threat signal
- Catches adversarial attacks targeting single-model blind spots

Based on research:
"If prompt guard says 'safe' but embedding model says 'attack-like',
that disagreement itself is a risk signal"
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class LayerResult:
    """Result from a single detection layer."""

    layer_name: str
    is_threat: bool
    confidence: float
    method: str
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnsembleAnalysis:
    """Analysis of ensemble disagreement."""

    disagreement_score: float  # 0-1, higher = more disagreement
    agreement_level: str  # "high", "medium", "low"
    threat_votes: int  # Number of layers voting "threat"
    safe_votes: int  # Number of layers voting "safe"
    avg_confidence: float  # Average confidence across layers
    confidence_variance: float  # Variance in confidence scores
    should_escalate: bool  # Whether to escalate for manual review
    final_decision: bool  # Final ensemble decision (is_threat)
    final_confidence: float  # Final ensemble confidence
    reasoning: str  # Explanation of ensemble decision


class EnsembleDisagreementDetector:
    """
    Detect and analyze disagreement between multiple detection layers.

    Uses voting, confidence analysis, and disagreement scoring to:
    1. Make more robust final decisions
    2. Identify adversarial attacks that fool single models
    3. Flag ambiguous cases for human review
    """

    def __init__(
        self,
        disagreement_threshold: float = 0.4,
        escalation_threshold: float = 0.6,
        min_layers: int = 2,
    ):
        """
        Initialize ensemble disagreement detector.

        Args:
            disagreement_threshold: Above this, consider disagreement significant
            escalation_threshold: Above this, escalate to manual review
            min_layers: Minimum layers needed for ensemble analysis
        """
        self.disagreement_threshold = disagreement_threshold
        self.escalation_threshold = escalation_threshold
        self.min_layers = min_layers

        # Statistics
        self.stats = {
            "total_analyses": 0,
            "high_disagreement": 0,
            "escalated": 0,
            "unanimous_safe": 0,
            "unanimous_threat": 0,
        }

    def analyze_ensemble(
        self,
        layer_results: List[LayerResult],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EnsembleAnalysis:
        """
        Analyze results from multiple detection layers.

        Args:
            layer_results: Results from different detection layers
            metadata: Additional context

        Returns:
            EnsembleAnalysis with disagreement metrics and final decision
        """
        self.stats["total_analyses"] += 1
        metadata = metadata or {}

        if len(layer_results) < self.min_layers:
            # Not enough layers for ensemble analysis
            return self._single_layer_fallback(layer_results)

        # Count votes
        threat_votes = sum(1 for r in layer_results if r.is_threat)
        safe_votes = len(layer_results) - threat_votes

        # Calculate disagreement score
        disagreement_score = self._calculate_disagreement(layer_results)

        # Calculate confidence metrics
        confidences = [r.confidence for r in layer_results]
        avg_confidence = np.mean(confidences)
        confidence_variance = np.var(confidences)

        # Determine agreement level
        agreement_level = self._get_agreement_level(disagreement_score)

        # Make final decision using weighted voting
        final_decision, final_confidence = self._make_final_decision(
            layer_results, disagreement_score
        )

        # Decide if should escalate
        should_escalate = self._should_escalate(
            disagreement_score, confidence_variance, threat_votes, safe_votes
        )

        # Generate reasoning
        reasoning = self._generate_reasoning(
            layer_results, disagreement_score, final_decision, should_escalate
        )

        # Update statistics
        if disagreement_score >= self.disagreement_threshold:
            self.stats["high_disagreement"] += 1
        if should_escalate:
            self.stats["escalated"] += 1
        if threat_votes == len(layer_results):
            self.stats["unanimous_threat"] += 1
        if safe_votes == len(layer_results):
            self.stats["unanimous_safe"] += 1

        return EnsembleAnalysis(
            disagreement_score=disagreement_score,
            agreement_level=agreement_level,
            threat_votes=threat_votes,
            safe_votes=safe_votes,
            avg_confidence=avg_confidence,
            confidence_variance=confidence_variance,
            should_escalate=should_escalate,
            final_decision=final_decision,
            final_confidence=final_confidence,
            reasoning=reasoning,
        )

    def _calculate_disagreement(self, layer_results: List[LayerResult]) -> float:
        """
        Calculate disagreement score (0-1).

        High disagreement indicates:
        - Layers voting differently (some threat, some safe)
        - High variance in confidence scores
        - Potential adversarial attack targeting specific models
        """
        # Component 1: Vote disagreement (normalized)
        threat_votes = sum(1 for r in layer_results if r.is_threat)
        vote_ratio = threat_votes / len(layer_results)
        # Maximum disagreement at 50/50 split
        vote_disagreement = 1 - abs(vote_ratio - 0.5) * 2

        # Component 2: Confidence variance (normalized)
        confidences = [r.confidence for r in layer_results]
        confidence_variance = np.var(confidences)
        # Normalize: max variance is 0.25 (for 0.5 std dev)
        confidence_disagreement = min(confidence_variance / 0.25, 1.0)

        # Component 3: Extreme disagreement (one says very confident threat, another very confident safe)
        extreme_disagreement = 0.0
        for i, r1 in enumerate(layer_results):
            for r2 in layer_results[i + 1 :]:
                if r1.is_threat != r2.is_threat:
                    if r1.confidence > 0.8 and r2.confidence > 0.8:
                        extreme_disagreement = 1.0
                        break

        # Weighted combination
        disagreement = (
            0.5 * vote_disagreement + 0.3 * confidence_disagreement + 0.2 * extreme_disagreement
        )

        return float(disagreement)

    def _get_agreement_level(self, disagreement_score: float) -> str:
        """Categorize agreement level."""
        if disagreement_score >= 0.6:
            return "low"
        elif disagreement_score >= 0.3:
            return "medium"
        else:
            return "high"

    def _make_final_decision(
        self,
        layer_results: List[LayerResult],
        disagreement_score: float,
    ) -> tuple[bool, float]:
        """
        Make final ensemble decision using weighted voting.

        Weights:
        - Higher confidence gets more weight
        - High disagreement reduces confidence
        - Threat detection is slightly favored (security-first)
        """
        # Weighted voting by confidence
        weighted_threat_score = 0.0
        total_weight = 0.0

        for result in layer_results:
            weight = result.confidence
            total_weight += weight

            if result.is_threat:
                weighted_threat_score += weight

        if total_weight == 0:
            # Fallback: simple majority
            threat_votes = sum(1 for r in layer_results if r.is_threat)
            return threat_votes > len(layer_results) / 2, 0.5

        # Calculate threat probability
        threat_probability = weighted_threat_score / total_weight

        # Adjust for disagreement (reduce confidence when disagreement is high)
        confidence_penalty = disagreement_score * 0.3
        adjusted_confidence = threat_probability * (1 - confidence_penalty)

        # Security-first: slight bias toward threat detection
        # If close to threshold, favor threat
        threshold = 0.5
        is_threat = adjusted_confidence >= threshold

        # Final confidence considering disagreement
        final_confidence = max(0.0, min(1.0, adjusted_confidence))

        return is_threat, final_confidence

    def _should_escalate(
        self,
        disagreement_score: float,
        confidence_variance: float,
        threat_votes: int,
        safe_votes: int,
    ) -> bool:
        """
        Decide if case should be escalated to manual review.

        Escalation criteria:
        - High disagreement score
        - High confidence variance
        - Close vote split
        """
        # Criterion 1: High disagreement
        if disagreement_score >= self.escalation_threshold:
            return True

        # Criterion 2: High variance with non-unanimous vote
        if confidence_variance > 0.15 and min(threat_votes, safe_votes) > 0:
            return True

        # Criterion 3: Close split with confident predictions
        total_votes = threat_votes + safe_votes
        if total_votes >= 3:
            vote_ratio = min(threat_votes, safe_votes) / total_votes
            if 0.3 <= vote_ratio <= 0.5:  # Close split
                return True

        return False

    def _generate_reasoning(
        self,
        layer_results: List[LayerResult],
        disagreement_score: float,
        final_decision: bool,
        should_escalate: bool,
    ) -> str:
        """Generate human-readable reasoning for the ensemble decision."""
        threat_count = sum(1 for r in layer_results if r.is_threat)
        safe_count = len(layer_results) - threat_count

        reasoning_parts = []

        # Vote summary
        reasoning_parts.append(
            f"Ensemble of {len(layer_results)} layers: "
            f"{threat_count} detected threat, {safe_count} detected safe"
        )

        # Disagreement level
        if disagreement_score >= 0.6:
            reasoning_parts.append(f"HIGH disagreement detected (score: {disagreement_score:.3f})")
        elif disagreement_score >= 0.3:
            reasoning_parts.append(f"MEDIUM disagreement (score: {disagreement_score:.3f})")

        # Layer details
        layer_names = [r.layer_name for r in layer_results if r.is_threat]
        if layer_names:
            reasoning_parts.append(f"Threat detected by: {', '.join(layer_names)}")

        # Escalation
        if should_escalate:
            reasoning_parts.append("⚠️ ESCALATED for manual review due to high disagreement")

        # Final decision
        decision_str = "THREAT" if final_decision else "SAFE"
        reasoning_parts.append(f"Final decision: {decision_str}")

        return " | ".join(reasoning_parts)

    def _single_layer_fallback(self, layer_results: List[LayerResult]) -> EnsembleAnalysis:
        """Fallback when only one layer available."""
        if not layer_results:
            return EnsembleAnalysis(
                disagreement_score=0.0,
                agreement_level="high",
                threat_votes=0,
                safe_votes=0,
                avg_confidence=0.0,
                confidence_variance=0.0,
                should_escalate=False,
                final_decision=False,
                final_confidence=0.0,
                reasoning="No layer results available",
            )

        result = layer_results[0]
        return EnsembleAnalysis(
            disagreement_score=0.0,
            agreement_level="high",
            threat_votes=1 if result.is_threat else 0,
            safe_votes=0 if result.is_threat else 1,
            avg_confidence=result.confidence,
            confidence_variance=0.0,
            should_escalate=False,
            final_decision=result.is_threat,
            final_confidence=result.confidence,
            reasoning=f"Single layer ({result.layer_name}): {result.reason}",
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get disagreement detection statistics."""
        total = self.stats["total_analyses"]
        if total == 0:
            return self.stats

        return {
            **self.stats,
            "high_disagreement_rate": self.stats["high_disagreement"] / total,
            "escalation_rate": self.stats["escalated"] / total,
            "unanimous_rate": (self.stats["unanimous_safe"] + self.stats["unanimous_threat"])
            / total,
        }

    def log_stats(self):
        """Log statistics."""
        stats = self.get_stats()
        logger.info(
            f"Ensemble Disagreement Stats: "
            f"{stats['total_analyses']} analyses, "
            f"{stats.get('high_disagreement_rate', 0):.1%} high disagreement, "
            f"{stats.get('escalation_rate', 0):.1%} escalated"
        )
