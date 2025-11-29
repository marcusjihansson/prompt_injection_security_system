# Threat Detection Hybrid System (Regex + DSPy)

A demo-ready hybrid security system for LLM agents. It combines a fast regex baseline with an optimized DSPy detector and a production-oriented fusion policy. Python and TypeScript runtimes included.

This repository implements a hybrid threat detection system that combines a fast, rule-based regex baseline with a learned
DSPy program (GEPA) for nuanced decisions. It is production-focused, configurable, and test-backed.

Highlights:

- Fast-path regex guardrails with high-severity short-circuiting
- DSPy-based detector with fusion logic for borderline cases
- Externalized regex patterns via JSON for easy updates
- Demo script to showcase protections without API keys
- FastAPI microservice and Dockerfile for quick deployment
- Clean metrics and unit tests

---

## Quickstart

Company-demo TL;DR:

- Everything runs offline by default; no API keys required for the core demo.
- Optional: add an OPENROUTER_API_KEY to showcase DSPy-driven inference.

Prerequisites:

- Python 3.11+
- Optional: OPENROUTER_API_KEY (only needed if using the OpenRouter-backed DSPy detector)

Install:

- We recommend using uv (already configured via pyproject.toml).
  - uv sync
- Or, using pip:
  - python -m venv .venv && source .venv/bin/activate
  - pip install -e .

Run demo (no API keys needed):

- python demo.py
  - Shows blocking vs safe outcomes using the regex baseline fast-path.
- uvicorn production.api:app --reload
  - Start the API service at http://localhost:8000 (offline by default)
- docker build -t threat-guard . && docker run -p 8000:8000 threat-guard
  - Run the API in a container

Run tests:

- pytest -q

---

## Architecture

- threat_system/
  - regex_baseline.py: Fast regex-based detector. Compiles patterns once, returns RegexResult(threats, severity, matches).
    Can load patterns from JSON.
  - threat_types.py: Enumerates threat categories for consistent classification.
  - metric.py: Metric utilities used by optimization/training; penalizes false negatives on high-severity regex matches.
  - config.py: Lazy configuration accessors (e.g., get_model_config) to avoid import-time failures without API keys.
- production/
  - deploy.py: ProductionThreatDetector orchestrates regex-first detection, DSPy detector inference, fusion logic, and metrics.
  - main.py: Entrypoint for running the service (FastAPI app).
- optimizer/
  - train_gepa.py: Training/optimization script for the DSPy program.
- threat_detector_optimized/: Saved DSPy program versions.
- tests/: Unit tests for regex baseline and fusion behavior.

### Fusion policy (summary)

- Stage A: Regex baseline
  - If high severity, immediately block with high confidence.
- Stage B: DSPy detector
  - If low severity regex signals exist and detector also flags threat, boost confidence.
  - If detector says benign but regex had low severity signals, override to threat with minimum confidence.

---

## Configuration

OpenRouter (optional):

- Set OPENROUTER_API_KEY in your environment to use the OpenRouter-backed DSPy model.
- Optional env vars:
  - OPENROUTER_MODEL (default: openrouter/openai/gpt-oss-safeguard-20b)
  - OPENROUTER_API_BASE (default: https://openrouter.ai/api/v1)
  - MAX_TOKENS (default: 1024)
  - TEMPERATURE (default: 0.0)
- Training-specific env vars for GEPA (threat_types/utility.setup_two_model_gepa):
  - TRAINING_LM_MODEL (default: openrouter/openai/gpt-oss-safeguard-20b)
  - REFLECTION_LM_MODEL (default: openrouter/openai/gpt-oss-safeguard-20b)
  - TRAINING_LM_MAX_TOKENS (default: 2048)
  - REFLECTION_LM_MAX_TOKENS (default: 1024)
  - TRAINING_TEMPERATURE (default: 0.0)
- The code fetches keys lazily via get_openrouter_api_key() and get_model_config(), so imports work even without keys.

Detector configuration knobs in ProductionThreatDetector (production/deploy.py):

- use_openrouter: bool – whether to initialize using OpenRouter.
- enable_regex_baseline: bool – enable the regex fast-path.
- detector_override: callable – inject a mock or custom detector (useful for tests).
- skip_model_setup: bool – skip LM initialization (useful in tests/demo).

---

## Regex patterns: externalized JSON

File: threat_system/regex_patterns.json

- patterns: map of ThreatType names to lists of regex patterns.
- high_severity_types: list of ThreatType names that should short-circuit and block.

Example snippet:

```
{
  "patterns": {
    "SYSTEM_PROMPT_ATTACK": [
      "(?i)reveal\\s+(?:your|the)\\s+(?:system\\s+)?prompt"
    ],
    "PROMPT_INJECTION": [
      "(?i)ignore\\s+(?:previous|all|your)\\s+(?:instructions?|prompts?|rules?)"
    ]
  },
  "high_severity_types": [
    "SYSTEM_PROMPT_ATTACK",
    "AUTH_BYPASS",
    "CODE_INJECTION",
    "DATA_EXFILTRATION"
  ]
}
```

Usage:

- RegexBaseline loads threat_system/regex_patterns.json automatically if present.
- You can also pass patterns_path explicitly when constructing RegexBaseline.

Best practices:

- Prefer precise, scoped patterns to avoid false positives.
- Keep high_severity_types focused on categories that require immediate blocking.

---

## Demo

A simple demo script is provided at repo root:

- demo.py
  - Loads a system prompt from system_prompt/system_prompt.json
  - Uses ProductionThreatDetector with regex baseline only (no API keys required)
  - Shows a blocked case and a benign case

Run:

- python demo.py

Customize:

- Edit system_prompt/system_prompt.json to change the demo’s system prompt.
- Set SYSTEM_PROMPT_PATH env var to point to a different JSON file.

---

## Running tests

- Unit tests:
  - pytest -q
- What’s covered:
  - Regex baseline classification
  - Fusion behavior (with a mock detector)

---

## Project structure

- demo.py – Quick demo entrypoint
- system_prompt/ – Demo system prompt JSON
- production/
  - deploy.py – ProductionThreatDetector (regex + DSPy + fusion + metrics)
  - main.py – FastAPI app setup
- threat_system/
  - regex_baseline.py – Regex baseline with externalized patterns
  - regex_patterns.json – Editable patterns for detection
  - threat_types.py – Threat types enum
  - metric.py – Metric utilities
  - config.py – Lazy config helpers
- optimizer/
  - train_gepa.py – Training/optimization pipeline

### Datasets for training

Datasets are configured in threat_system/config.py via DATASET_CONFIG. You can add entries in two ways:

- Simple (string):
  "prompt_injection_dataset": "deepset/prompt-injections"
  - Threat type inferred from key name.

- Advanced (dict):
  "xtram1_safe_guard_prompt_injection": {
  "path": "xTRam1/safe-guard-prompt-injection",
  "split": "train",
  "threat_type": "PROMPT_INJECTION",
  "size": 100
  }

- size parameter controls how many examples to use from that dataset.
- Additional optional fields: is_threat, text_fields.

The training script automatically aggregates all configured datasets:

- uv run optimizer/train_gepa.py

- tests/
  - test_regex_baseline.py – Unit tests for regex baseline
  - test_fusion.py – Unit tests for fusion logic

---

## Development & contributions

- Add new patterns in regex_patterns.json and open a PR explaining the rationale and any false-positive risks.
- Expand tests when adding patterns or changing fusion policy.
- Keep high-severity categories narrowly scoped.
- If integrating new data sources or detectors, prefer config flags and dependency-injection friendly constructors.

---

## Security considerations

- High-severity categories block immediately with high confidence.
- Regex patterns should be reviewed for performance (avoid catastrophic backtracking). Prefer non-backtracking constructs and keep inputs bounded.
- Consider logging and tracing (PII safe) in production to analyze false positives/negatives.

---

## Contact details

- X: marcusjihansson
