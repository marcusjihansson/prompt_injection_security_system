"""
Confidence-Based Routing for Multi-Layer Detection

Implements Priority 2 from research plan: Skip expensive layers when confidence is extreme.

Key Features:
- Early exit on high-confidence detections (>85% confidence → block immediately)
- Skip expensive layers on obvious safe inputs (<5% confidence → allow)
- Route ambiguous cases (5-85% confidence) through full pipeline
- Expected latency reduction: 60-70% for obvious cases

Based on research:
"If prompt guard confidence < 2% → skip embedding + output guard"
"If confidence 2–15% → run embedding model"
"If >15% → block or escalate immediately"
"""

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RoutingDecision:
    """Decision about which layers to execute."""

    skip_embedding: bool = False
    skip_ml_detector: bool = False
    skip_output_guard: bool = False
    early_exit: bool = False
    reason: str = ""
    confidence_level: str = "medium"  # low, medium, high


class ConfidenceRouter:
    """
    Routes detection through layers based on confidence thresholds.

    Confidence Ranges:
    - SAFE (0-5%): Obviously safe → skip expensive layers
    - LOW (5-20%): Likely safe but uncertain → run embedding check
    - MEDIUM (20-85%): Ambiguous → run full pipeline
    - HIGH (85-95%): Likely threat → run full validation
    - CRITICAL (95-100%): Definite threat → block immediately
    """

    def __init__(
        self,
        safe_threshold: float = 0.05,
        low_threshold: float = 0.20,
        high_threshold: float = 0.85,
        critical_threshold: float = 0.95,
    ):
        """
        Initialize confidence router.

        Args:
            safe_threshold: Below this, skip expensive layers (default 5%)
            low_threshold: Below this, skip ML but run embedding (default 20%)
            high_threshold: Above this, run full validation (default 85%)
            critical_threshold: Above this, block immediately (default 95%)
        """
        self.safe_threshold = safe_threshold
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold

        # Statistics tracking
        self.stats = {
            "total_requests": 0,
            "early_exits": 0,
            "skipped_embedding": 0,
            "skipped_ml": 0,
            "skipped_output_guard": 0,
            "full_pipeline": 0,
        }

    def route(
        self,
        confidence: float,
        is_threat: bool,
        layer: str = "regex",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RoutingDecision:
        """
        Decide which layers to execute based on confidence.

        Args:
            confidence: Confidence score from current layer (0-1)
            is_threat: Whether current layer detected a threat
            layer: Which layer produced this confidence ("regex", "embedding", etc.)
            metadata: Additional context

        Returns:
            RoutingDecision with skip flags and reasoning
        """
        self.stats["total_requests"] += 1
        metadata = metadata or {}

        # CRITICAL: Definite threat → block immediately
        if is_threat and confidence >= self.critical_threshold:
            self.stats["early_exits"] += 1
            return RoutingDecision(
                skip_embedding=True,
                skip_ml_detector=True,
                skip_output_guard=True,
                early_exit=True,
                reason=f"Critical threat detected by {layer} (confidence: {confidence:.3f})",
                confidence_level="critical",
            )

        # HIGH: Likely threat → run full validation for confidence
        if is_threat and confidence >= self.high_threshold:
            return RoutingDecision(
                skip_embedding=False,
                skip_ml_detector=False,
                skip_output_guard=False,
                early_exit=False,
                reason=f"High confidence threat from {layer}, running full validation",
                confidence_level="high",
            )

        # SAFE: Obviously safe → skip expensive layers
        if not is_threat and confidence <= self.safe_threshold:
            self.stats["skipped_embedding"] += 1
            self.stats["skipped_ml"] += 1
            self.stats["skipped_output_guard"] += 1
            return RoutingDecision(
                skip_embedding=True,
                skip_ml_detector=True,
                skip_output_guard=True,
                early_exit=True,
                reason=f"Very low threat confidence from {layer} (confidence: {confidence:.3f})",
                confidence_level="safe",
            )

        # LOW: Likely safe but uncertain → run embedding check only
        if not is_threat and confidence <= self.low_threshold:
            self.stats["skipped_ml"] += 1
            return RoutingDecision(
                skip_embedding=False,  # Run embedding check
                skip_ml_detector=True,  # Skip expensive ML
                skip_output_guard=False,  # Still check output
                early_exit=False,
                reason=f"Low confidence from {layer}, running embedding check",
                confidence_level="low",
            )

        # MEDIUM: Ambiguous → run full pipeline
        self.stats["full_pipeline"] += 1
        return RoutingDecision(
            skip_embedding=False,
            skip_ml_detector=False,
            skip_output_guard=False,
            early_exit=False,
            reason=f"Medium confidence from {layer}, running full pipeline",
            confidence_level="medium",
        )

    def should_escalate(
        self,
        results: List[Dict[str, Any]],
    ) -> bool:
        """
        Decide if detection should be escalated based on multiple layer results.

        Args:
            results: List of detection results from different layers

        Returns:
            True if should escalate to manual review
        """
        # Escalate if any layer has high confidence threat
        for result in results:
            if result.get("is_threat") and result.get("confidence", 0) >= self.high_threshold:
                return True

        # Escalate if multiple layers disagree (see Priority 3)
        threat_count = sum(1 for r in results if r.get("is_threat"))
        if len(results) >= 3 and 0 < threat_count < len(results):
            # Some say threat, some say safe → disagreement
            return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get routing statistics."""
        total = self.stats["total_requests"]
        if total == 0:
            return self.stats

        return {
            **self.stats,
            "early_exit_rate": self.stats["early_exits"] / total,
            "full_pipeline_rate": self.stats["full_pipeline"] / total,
            "avg_layers_skipped": (
                self.stats["skipped_embedding"]
                + self.stats["skipped_ml"]
                + self.stats["skipped_output_guard"]
            )
            / total,
        }

    def reset_stats(self):
        """Reset statistics."""
        for key in self.stats:
            self.stats[key] = 0

    def log_stats(self):
        """Log current statistics."""
        stats = self.get_stats()
        logger.info(
            f"Confidence Router Stats: "
            f"{stats['total_requests']} requests, "
            f"{stats['early_exit_rate']:.1%} early exits, "
            f"{stats['full_pipeline_rate']:.1%} full pipeline"
        )
