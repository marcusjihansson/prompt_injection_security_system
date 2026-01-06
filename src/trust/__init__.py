"""
Trust - Hybrid Threat Detection System with Chain of Trust Security Framework

A production-ready security layer for AI systems combining:
- DSPy-based LLM threat detection
- Regex baseline for fast pre-filtering
- Multi-layered Chain of Trust (input guard, core logic, output guard)
- Self-learning shield with failure logging
- Semantic caching and request deduplication

Usage:
    import dspy
    from trust import Trust

    my_bot = dspy.ChainOfThought("question -> answer")
    trusted_bot = Trust(my_bot)
    result = trusted_bot("What is the capital of France?")
"""

from trust.api.api import create_app

# API components
from trust.api.app import create_fastapi_app
from trust.core.config import (
    BASELINE_PATTERNS_PATH,
    GEPA_MODEL_PATH,
    get_cache_config,
    get_training_config,
)

# Core threat detection
from trust.core.detector import ThreatDetectionSignature, ThreatDetector
from trust.core.metric import threat_detection_metric_with_feedback
from trust.core.regex_baseline import RegexBaseline, RegexResult
from trust.core.threat_types import ThreatType

# Security guards
from trust.guards.input_guard import FailureExample, SelfLearningShield
from trust.guards.output_guard import OutputGuard, OutputGuardResult, OutputViolationType
from trust.guards.primitives import SecureField, TrustLevel
from trust.guards.prompt_builder import SecurePromptBuilder
from trust.guards.prompt_cache import PromptCache
from trust.guards.security_policy import Capability, CapabilityEnforcer, SecurityPolicy
from trust.guards.trusted_layer import TrustedLayer
from trust.production.caches.request_dedup import RequestDeduplicator
from trust.production.caches.semantic_cache import SemanticCache

# Production components
from trust.production.detectors.detector import ProductionThreatDetector
from trust.production.models.lm import SecurityModel, security_model
from trust.production.models.ml import (
    OptimizedThreatDetector,
    create_input_guard_from_optimized,
    list_available_versions,
    load_optimized_detector,
)

# Main Trust wrapper
from trust.trust import Trust

__version__ = "1.0.0"

__all__ = [
    # Core
    "ThreatDetector",
    "ThreatDetectionSignature",
    "ThreatType",
    "RegexBaseline",
    "RegexResult",
    "threat_detection_metric_with_feedback",
    # Guards
    "SelfLearningShield",
    "FailureExample",
    "OutputGuard",
    "OutputViolationType",
    "OutputGuardResult",
    "TrustLevel",
    "SecureField",
    "SecurePromptBuilder",
    "PromptCache",
    "SecurityPolicy",
    "Capability",
    "CapabilityEnforcer",
    "TrustedLayer",
    # Production
    "ProductionThreatDetector",
    "SemanticCache",
    "RequestDeduplicator",
    "security_model",
    "SecurityModel",
    "load_optimized_detector",
    "create_input_guard_from_optimized",
    "OptimizedThreatDetector",
    "list_available_versions",
    # Main API
    "Trust",
    # API Server
    "create_fastapi_app",
    "create_app",
    # Config
    "GEPA_MODEL_PATH",
    "BASELINE_PATTERNS_PATH",
    "get_training_config",
    "get_cache_config",
]
