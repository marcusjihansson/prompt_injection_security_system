"""
Core threat detection components.
"""

from trust.core.config import (
    BASELINE_PATTERNS_PATH,
    GEPA_MODEL_PATH,
    get_adaptive_detection_config,
    get_cache_config,
    get_connection_pool_config,
    get_training_config,
    get_valkey_config,
)
from trust.core.detector import ThreatDetectionSignature, ThreatDetector
from trust.core.metric import threat_detection_metric_with_feedback
from trust.core.regex_baseline import RegexBaseline, RegexResult
from trust.core.threat_types import ThreatType

__all__ = [
    "ThreatDetector",
    "ThreatDetectionSignature",
    "ThreatType",
    "RegexBaseline",
    "RegexResult",
    "threat_detection_metric_with_feedback",
    "GEPA_MODEL_PATH",
    "BASELINE_PATTERNS_PATH",
    "get_training_config",
    "get_cache_config",
    "get_valkey_config",
    "get_adaptive_detection_config",
    "get_connection_pool_config",
]
