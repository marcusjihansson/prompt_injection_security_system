"""
Interactive demo showing how the security system guards a call.

This demo works the same way as the last demo, but this demo shows potential gaps
in the security system, which is a sign of the system needing further optimization.

I still wanted to show this, for the following reasons:
A) This is a sign that this demo is not production ready, as this demo needs further
optimization by its training data selection
B) This shows that this prototype works, but it is still a prototype and advanced prompt attacks
as well as other attack patterns such as server attacks has the current prototype not taking into
account for
C) This prototype shows that a security system with both: detector + gepa is a working system

Run: python advanced_demo.py
"""

import json
import os
import sys
from pathlib import Path

from trust import ProductionThreatDetector


class MockDetector:
    """Mock detector for offline demo mode to suppress DSPy errors."""

    def __call__(self, input_text, **kwargs):
        return {
            "is_threat": False,
            "threat_type": "benign",
            "confidence": 0.0,
            "reasoning": "Offline demo: DSPy detector skipped (Regex only)",
        }


class DemoThreatDetector(ProductionThreatDetector):
    """
    Wrapper around ProductionThreatDetector that allows for mocking components
    and ignoring unsupported legacy arguments for demo purposes.
    """

    def __init__(self, detector_override=None, **kwargs):
        # Filter out arguments not supported by the real ProductionThreatDetector
        enable_regex = kwargs.get("enable_regex_baseline", False)
        super().__init__(enable_regex_baseline=enable_regex)

        self.detector_override = detector_override

    def detect_threat(self, input_text: str):
        # If we have an override (MockDetector), use it for the "LLM" part
        if self.regex_baseline:
            regex_result = self.regex_baseline.check(input_text)
            if regex_result.severity >= 3:
                return {
                    "is_threat": True,
                    "threat_type": (
                        next(iter(regex_result.threats)).value
                        if regex_result.threats
                        else "prompt_injection"
                    ),
                    "confidence": 0.95,
                    "reasoning": f"Regex baseline high-severity match: {list(regex_result.threats)}",
                }

        # Fallback to override if provided (simulating the LLM)
        if self.detector_override:
            return self.detector_override(input_text)

        return super().detect_threat(input_text)


def load_system_prompt(path: str) -> str:
    p = Path(path)
    if not p.exists():
        # Fallback if file doesn't exist
        return "You are a helpful assistant."
    try:
        data = json.loads(p.read_text())
    except Exception:
        return "You are a helpful assistant."
    return data.get("system_prompt", "")


def load_advanced_queries(path: str) -> list:
    p = Path(path)
    if not p.exists():
        # Fallback if file doesn't exist
        return []
    try:
        data = json.loads(p.read_text())
    except Exception:
        return []
    examples = []
    prompt_injection_tests = data.get("prompt_injection_tests", {})
    for category, texts in prompt_injection_tests.items():
        # Extract expected_type from category, e.g., "1_direct_instruction_override" -> "DIRECT_INSTRUCTION_OVERRIDE"
        parts = category.split("_")
        if len(parts) > 1:
            expected_type = "_".join(parts[1:]).upper()
        else:
            expected_type = category.upper()
        for text in texts:
            examples.append((text, expected_type))
    return examples


def guarded_call(user_input: str, system_prompt: str, detector: ProductionThreatDetector):
    # Check input with the threat detector first
    result = detector.detect_threat(user_input)

    print(f"Input:     {user_input}")

    if result["is_threat"]:
        print(f"Decision:  \033[91m[BLOCKED]\033[0m Threat detected")
        print(f"Type:      {result['threat_type']}")
        print(f"Reason:    {result['reasoning']}")
        return None
    else:
        print(f"Decision:  \033[92m[ALLOWED]\033[0m Safe to process")
        print(f"Reason:    {result['reasoning']}")
        # Simulate calling a downstream model or function
        return f"[System Response] Proceeding with safe request. (Protected system prompt length: {len(system_prompt)} chars)"


def main():
    # Load a sample system prompt
    sys_prompt_path = os.getenv("SYSTEM_PROMPT_PATH", "system_prompt/system_prompt.json")
    system_prompt = load_system_prompt(sys_prompt_path)

    # Initialize detector with regex baseline and MockDetector
    # This allows the demo to run without API keys while showing regex capabilities
    detector = DemoThreatDetector(
        use_openrouter=True,
        enable_regex_baseline=True,
        skip_model_setup=True,
        detector_override=MockDetector(),
    )

    print("\n" + "=" * 70)
    print("🔒 Threat Detection System Demo")
    print("=" * 70)
    print("Running in OFFLINE mode (Regex Baseline enabled, LLM skipped)")
    print("-" * 70)

    # 1. Run Automated Examples
    print("\n📊 Advanced Test Queries:\n")

    queries_path = os.getenv("ADVANCED_QUERIES_PATH", "tests/advanced_examples.json")
    examples = load_advanced_queries(queries_path)

    for text, expected_type in examples:
        guarded_call(text, system_prompt, detector)
        print("-" * 70)

    # 2. Interactive Mode
    print("\n🎮 Interactive Mode")
    print("Type a prompt to test the guardrails (or 'q' to quit)")
    print("-" * 70)

    while True:
        try:
            user_input = input("\n> ").strip()
            if user_input.lower() in ("q", "quit", "exit"):
                print("Exiting demo. Goodbye!")
                break

            if not user_input:
                continue

            guarded_call(user_input, system_prompt, detector)

        except KeyboardInterrupt:
            print("\nExiting demo. Goodbye!")
            break


if __name__ == "__main__":
    main()
