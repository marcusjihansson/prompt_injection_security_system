"""
Central configuration for GEPA threat detection system
"""

import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv

load_dotenv()

# API Keys (lazy retrieval to avoid import-time failures in tests)


def get_openrouter_api_key() -> str:
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")
    return key


# Model Configuration factory (avoid resolving API key on import)


def get_model_config() -> Dict[str, Any]:
    return {
        "model": "openrouter/openai/gpt-oss-safeguard-20b",
        "api_base": "https://openrouter.ai/api/v1",
        "api_key": get_openrouter_api_key(),
        "max_tokens": 512,
        "temperature": 0.0,
        "cache": True,
    }


# Paths - Use absolute path to project root to work from any directory
# Find project root by looking for pyproject.toml or .git directory
def _find_project_root() -> Path:
    """Find the project root directory."""
    current = Path(__file__).resolve().parent
    # Navigate up from src/trust/core/ to project root
    while current != current.parent:
        if (current / "pyproject.toml").exists() or (current / ".git").exists():
            return current
        current = current.parent
    # Fallback: assume we're in src/trust/core and go up 3 levels
    return Path(__file__).resolve().parent.parent.parent


_PROJECT_ROOT = _find_project_root()
THREAT_DETECTOR_BASE_DIR = str(_PROJECT_ROOT / "threat_detector_optimized")
GEPA_MODEL_PATH = f"{THREAT_DETECTOR_BASE_DIR}/latest/program.json"
GEPA_METADATA_PATH = f"{THREAT_DETECTOR_BASE_DIR}/latest/metadata.json"
BASELINE_PATTERNS_PATH = "threat_system/regex_patterns.json"

# Security Settings
SECURITY_CONFIG = {
    "enable_llm_analysis": True,
    "max_requests_per_minute": 60,
    "max_input_length": 5000,
    "gepa_model_path": GEPA_MODEL_PATH,
}

# Local Security Model
try:
    from trust.production.lm import security_model
except ImportError:

    def security_model():
        raise ImportError("production.lm not found. Ensure 'production' package is available.")


# Training Settings
TRAINING_CONFIG = {
    "max_prompt_injection": int(os.getenv("MAX_PROMPT_INJECTION", 50)),
    "max_jailbreak": int(os.getenv("MAX_JAILBREAK", 50)),
    "budget": "light",  # 'light', 'medium', 'heavy'
}

# Dataset Settings
# You can specify datasets as simple strings or detailed dict entries.
# Dict entries support: path, split, threat_type, is_threat, text_fields, size (per-dataset limit)
DATASET_CONFIG = {
    "prompt_injection_dataset": {
        "path": "deepset/prompt-injections",
        "split": "train",
        "threat_type": "PROMPT_INJECTION",
        "size": int(os.getenv("MAX_PROMPT_INJECTION", 100)),
    },
    "jailbreak_dataset": {
        "path": "TrustAIRLab/in-the-wild-jailbreak-prompts",
        "name": "jailbreak_2023_12_25",
        "split": "train",
        "threat_type": "JAILBREAK",
        "size": int(os.getenv("MAX_JAILBREAK", 100)),
    },
    # Example additional dataset
    "xtram1_safe_guard_prompt_injection": {
        "path": "xTRam1/safe-guard-prompt-injection",
        "split": "train",
        "threat_type": "PROMPT_INJECTION",
        "size": int(os.getenv("MAX_XTRAM1_PI", 100)),
    },
    "benign_dataset": {
        "path": "OpenAssistant/oasst1",
        "split": "train",
        "column": "text",
        "threat_type": "BENIGN",
        "size": int(os.getenv("MAX_BENIGN", 100)),
    },
}


def get_training_config() -> Dict[str, Any]:
    """Get training configuration."""
    return TRAINING_CONFIG


def get_cache_config() -> Dict[str, Any]:
    """Get cache configuration."""
    return {
        "similarity_threshold": float(os.getenv("CACHE_SIMILARITY_THRESHOLD", "0.95")),
        "ttl": int(os.getenv("CACHE_TTL", "3600")),
        "l1_size": int(os.getenv("CACHE_L1_SIZE", "1024")),
        "l3_ttl": int(os.getenv("CACHE_L3_TTL", "3600")),
        "enable_l3": os.getenv("CACHE_ENABLE_L3", "true").lower() == "true",
    }


def get_valkey_config() -> Dict[str, Any]:
    """Get Valkey/Redis configuration."""
    return {
        "host": os.getenv("VALKEY_HOST", "localhost"),
        "port": int(os.getenv("VALKEY_PORT", "6379")),
        "db": int(os.getenv("VALKEY_DB", "0")),
        "password": os.getenv("VALKEY_PASSWORD"),
        "decode_responses": True,
        "socket_timeout": int(os.getenv("VALKEY_TIMEOUT", "5")),
        "socket_connect_timeout": int(os.getenv("VALKEY_CONNECT_TIMEOUT", "5")),
    }


def get_adaptive_detection_config() -> Dict[str, Any]:
    """Get adaptive detection configuration."""
    return {
        "enable_fast_path": os.getenv("ADAPTIVE_ENABLE_FAST_PATH", "true").lower() == "true",
        "confidence_threshold": float(os.getenv("ADAPTIVE_CONFIDENCE_THRESHOLD", "0.85")),
    }


def get_connection_pool_config() -> Dict[str, Any]:
    """Get connection pool configuration."""
    return {
        "max_connections": int(os.getenv("POOL_MAX_CONNECTIONS", "100")),
        "max_keepalive_connections": int(os.getenv("POOL_MAX_KEEPALIVE", "20")),
        "keepalive_expiry": float(os.getenv("POOL_KEEPALIVE_EXPIRY", "30.0")),
        "timeout": float(os.getenv("POOL_TIMEOUT", "30.0")),
    }
