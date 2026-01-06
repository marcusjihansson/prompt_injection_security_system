"""
Production-ready threat detection components.
"""

from trust.production.caches.multi_tier_cache import MultiTierCache
from trust.production.caches.request_dedup import RequestDeduplicator
from trust.production.caches.semantic_cache import SemanticCache
from trust.production.detectors.adaptive_detector import (
    AdaptiveDetector,
    create_adaptive_detector,
)
from trust.production.detectors.detector import ProductionThreatDetector
from trust.production.detectors.detector_enhanced import (
    EnhancedProductionThreatDetector,
)
from trust.production.detectors.embedding_anomaly_detector import (
    EmbeddingAnomalyDetector,
)
from trust.production.detectors.ensemble_disagreement import (
    EnsembleDisagreementDetector,
    LayerResult,
)
from trust.production.detectors.spotlighting import (
    DelimiterStyle,
    PromptSpotlighter,
    SpotlightingTransform,
)
from trust.production.models.lm import SecurityModel, security_model
from trust.production.models.ml import (
    OptimizedThreatDetector,
    create_input_guard_from_optimized,
    list_available_versions,
    load_optimized_detector,
)
from trust.production.utils.connection_pool import (
    ConnectionPoolManager,
    get_connection_pool,
    reset_connection_pool,
)

__all__ = [
    # Legacy detector
    "ProductionThreatDetector",
    # Enhanced detector with research-based improvements
    "EnhancedProductionThreatDetector",
    # Research-based enhancements (Priority 1-4)
    "EmbeddingAnomalyDetector",  # Priority 1: Embedding-based anomaly detection
    "EnsembleDisagreementDetector",  # Priority 3: Ensemble disagreement
    "LayerResult",  # Helper for ensemble analysis
    "PromptSpotlighter",  # Priority 4: Spotlighting
    "SpotlightingTransform",  # Priority 4: Spotlighting
    "DelimiterStyle",  # Priority 4: Delimiter styles
    # Caching
    "SemanticCache",
    "MultiTierCache",
    # Request handling
    "RequestDeduplicator",
    # Adaptive detection
    "AdaptiveDetector",
    "create_adaptive_detector",
    # Connection pooling
    "ConnectionPoolManager",
    "get_connection_pool",
    "reset_connection_pool",
    # Security models
    "security_model",
    "SecurityModel",
    # Optimized detectors
    "load_optimized_detector",
    "create_input_guard_from_optimized",
    "OptimizedThreatDetector",
    "list_available_versions",
]
