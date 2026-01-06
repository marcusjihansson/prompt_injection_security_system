"""
Utility functions for dataset loading and training example creation.

Supports automatic ingestion of datasets defined in DATASET_CONFIG with two formats:
- Simple string value (path to HF dataset): key name is used to infer threat type and text fields.
- Advanced dict value:
  {
    "path": "namespace/dataset",
    "split": "train",
    "threat_type": "PROMPT_INJECTION" | "JAILBREAK" | "BENIGN" | ... (ThreatType name),
    "is_threat": true/false,
    "text_fields": ["text", "prompt"],
    "max": 100
  }

If a dataset key cannot be inferred (e.g., a simple string with an unknown key), it is skipped with a warning.
"""

from typing import Any, Dict, Iterable, List, Optional

import dspy
from datasets import load_dataset

from trust.core.config import get_openrouter_api_key
from trust.core.threat_types import ThreatType


def _infer_threat_type_from_key(key: str) -> Optional[ThreatType]:
    k = key.lower()
    if "prompt_injection" in k:
        return ThreatType.PROMPT_INJECTION
    if "jailbreak" in k:
        return ThreatType.JAILBREAK
    if "benign" in k or "safe" in k or "harmless" in k:
        return ThreatType.BENIGN
    # Unknown
    return None


def _pick_text(item: Any, fields: Iterable[str]) -> str:
    if isinstance(item, dict):
        for f in fields:
            if f in item and isinstance(item[f], str) and item[f].strip():
                return item[f]
    # Fallbacks
    for f in fields:
        v = getattr(item, f, None)
        if isinstance(v, str) and v.strip():
            return v
    return str(item)


def create_training_examples(
    dataset_config: Dict[str, Any], training_config: Dict[str, Any]
) -> List[Dict[str, Any]]:
    examples: List[Dict[str, Any]] = []

    # Default field priorities
    default_fields = [
        "text",
        "prompt",
        "jailbreak_prompt",
        "input",
        "content",
        "instruction",
    ]

    # Heuristic caps when not provided
    default_max = int(training_config.get("max_per_dataset", 50))

    # Collect per-dataset summaries for logging
    summaries: List[Dict[str, Any]] = []

    for key, cfg in dataset_config.items():
        # Normalize config entry
        if isinstance(cfg, str):
            path = cfg
            split = "train"
            ttype = _infer_threat_type_from_key(key)
            if not ttype:
                print(
                    f"[dataset:{key}] Warning: Could not infer threat type from key; skipping dataset '{path}'"
                )
                continue
            is_threat = ttype is not ThreatType.BENIGN
            fields = (
                ["text", "prompt"]
                if ttype is ThreatType.PROMPT_INJECTION
                else (
                    ["jailbreak_prompt", "prompt", "text"]
                    if ttype is ThreatType.JAILBREAK
                    else default_fields
                )
            )
            max_items = (
                int(training_config.get("max_prompt_injection", default_max))
                if ttype is ThreatType.PROMPT_INJECTION
                else (
                    int(training_config.get("max_jailbreak", default_max))
                    if ttype is ThreatType.JAILBREAK
                    else default_max
                )
            )
        elif isinstance(cfg, dict):
            path = cfg.get("path") or cfg.get("dataset")
            if not path:
                print(f"[dataset:{key}] Warning: Missing 'path'; skipping")
                continue
            split = cfg.get("split", "train")
            ttype_name = cfg.get("threat_type")
            ttype = None
            if isinstance(ttype_name, str):
                try:
                    ttype = ThreatType[ttype_name]
                except Exception:
                    # Try value mapping
                    ttype = next((t for t in ThreatType if t.value == ttype_name), None)
            if ttype is None:
                ttype = _infer_threat_type_from_key(key) or ThreatType.BENIGN
            is_threat = bool(cfg.get("is_threat", ttype is not ThreatType.BENIGN))
            fields = cfg.get("text_fields") or default_fields
            if cfg.get("text_fields") is not None and not isinstance(
                cfg.get("text_fields"), (list, tuple)
            ):
                print(
                    f"[dataset:{key}] Warning: text_fields should be a list of field names; using defaults"
                )
                fields = default_fields
            max_items = int(cfg.get("size", cfg.get("max", default_max)))
        else:
            print(f"[dataset:{key}] Warning: Unsupported dataset config type; skipping")
            continue

        # Load dataset
        try:
            load_kwargs = {"split": split}
            if isinstance(cfg, dict) and cfg.get("name"):
                load_kwargs["name"] = cfg["name"]
            ds = load_dataset(path, **load_kwargs)
        except Exception as e:
            print(f"[dataset:{key}] Warning: Could not load dataset '{path}': {e}")
            continue

        # Iterate and collect
        collected = 0
        skipped_no_text = 0
        for item in ds:
            if collected >= max_items:
                break
            text = _pick_text(item, fields)
            if not text:
                skipped_no_text += 1
                continue
            examples.append(
                {
                    "input_text": text,
                    "is_threat": bool(is_threat),
                    "threat_type": ttype.value,
                }
            )
            collected += 1

        if collected == 0:
            print(
                f"[dataset:{key}] Warning: Collected 0 examples (path={path}, split={split}). Check text_fields: {fields}"
            )

        summaries.append(
            {
                "key": key,
                "path": path,
                "split": split,
                "threat_type": ttype.name,
                "is_threat": bool(is_threat),
                "requested": max_items,
                "collected": collected,
                "skipped_no_text": skipped_no_text,
            }
        )

    # Ensure some benign coverage if none provided
    if not any(not ex["is_threat"] for ex in examples):
        benign_examples = [
            "Write me an example email about reaching new customers.",
            "Tell me how to write a marketing email.",
            "What is the capital of France?",
            "Explain how photosynthesis works.",
            "How do I bake chocolate chip cookies?",
        ]
        for text in benign_examples:
            examples.append(
                {
                    "input_text": text,
                    "is_threat": False,
                    "threat_type": ThreatType.BENIGN.value,
                }
            )
        print("[benign] Added fallback benign examples to balance training set")

    # Summary logs
    print("\nDataset load summary:")
    for s in summaries:
        print(
            f" - {s['key']}: type={s['threat_type']} is_threat={s['is_threat']} "
            f"requested={s['requested']} collected={s['collected']} skipped_no_text={s['skipped_no_text']} "
            f"path={s['path']} split={s['split']}"
        )

    print(f"Total examples: {len(examples)} from {len(summaries)} dataset entries\n")
    return examples


def setup_two_model_gepa():
    """Configure DSPy for GEPA optimization with two models"""

    # Main model - makes predictions (this gets optimized by GEPA)
    main_lm = dspy.LM(
        model="openrouter/openai/gpt-4o-mini",
        api_key=get_openrouter_api_key(),
        api_base="https://openrouter.ai/api/v1",
        max_tokens=4096,
        temperature=0.1,  # Deterministic for security
        cache=True,
    )

    # Reflection model - evaluates predictions (guides GEPA optimization)
    reflection_lm = dspy.LM(
        model="openrouter/openai/gpt-oss-safeguard-20b",
        api_key=get_openrouter_api_key(),
        api_base="https://openrouter.ai/api/v1",
        max_tokens=4096,
        temperature=0.1,
        cache=False,  # Don't cache evaluations
    )

    dspy.configure(lm=main_lm)

    print("✅ Two-model GEPA setup complete!")
    print(f"Main LM (being optimized): llama-guard-3-8b")
    print(f"Reflection LM (optimizer): openai/gpt-oss-safeguard-20b")

    return main_lm, reflection_lm
