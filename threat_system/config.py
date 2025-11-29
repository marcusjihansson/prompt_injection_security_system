"""
Central configuration for GEPA threat detection system
"""

import os
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


# Paths
THREAT_DETECTOR_BASE_DIR = "threat_detector_optimized"
GEPA_MODEL_PATH = f"{THREAT_DETECTOR_BASE_DIR}/latest/program.json"
GEPA_METADATA_PATH = f"{THREAT_DETECTOR_BASE_DIR}/latest/metadata.json"

# Security Settings
SECURITY_CONFIG = {
    "enable_llm_analysis": True,
    "max_requests_per_minute": 60,
    "max_input_length": 5000,
    "gepa_model_path": GEPA_MODEL_PATH,
}

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
        "size": int(os.getenv("MAX_PROMPT_INJECTION", 50)),
    },
    "jailbreak_dataset": {
        "path": "TrustAIRLab/in-the-wild-jailbreak-prompts",
        "name": "jailbreak_2023_12_25",
        "split": "train",
        "threat_type": "JAILBREAK",
        "size": int(os.getenv("MAX_JAILBREAK", 50)),
    },
    # Example additional dataset
    "xtram1_safe_guard_prompt_injection": {
        "path": "xTRam1/safe-guard-prompt-injection",
        "split": "train",
        "threat_type": "PROMPT_INJECTION",
        "size": int(os.getenv("MAX_XTRAM1_PI", 100)),
    },
}
