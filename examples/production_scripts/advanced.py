import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from trust import ProductionThreatDetector


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


def analyze(results: list):
    from collections import defaultdict

    category_stats = defaultdict(
        lambda: {"total": 0, "allowed": 0, "blocked": 0, "false_neg": 0, "false_pos": 0}
    )

    for res in results:
        cat = res["expected_type"]
        category_stats[cat]["total"] += 1
        if res["is_threat"]:
            category_stats[cat]["blocked"] += 1
            # Assuming expected_type indicates threat if not benign
            if cat != "BENIGN":  # Adjust based on actual expected types
                pass  # Correct block
            else:
                category_stats[cat]["false_pos"] += 1
        else:
            category_stats[cat]["allowed"] += 1
            if cat != "BENIGN":
                category_stats[cat]["false_neg"] += 1

    print("\nAnalysis of Query Types:")
    print("=" * 60)
    for cat, stats in category_stats.items():
        total = stats["total"]
        allowed = stats["allowed"]
        blocked = stats["blocked"]
        false_neg = stats["false_neg"]
        false_pos = stats["false_pos"]
        detection_rate = (blocked / total * 100) if total > 0 else 0
        print(f"Category: {cat}")
        print(f"  Total: {total}, Allowed: {allowed}, Blocked: {blocked}")
        print(f"  False Negatives (threats missed): {false_neg}, False Positives: {false_pos}")
        print(f"  Detection Rate: {detection_rate:.1f}%")
        print("-" * 40)


def main():
    # Initialize the Production Threat Detector with regex baseline and LLM (GEPA optimization applied)
    detector = ProductionThreatDetector(enable_regex_baseline=True)

    # Load advanced test cases from JSON
    test_cases = load_advanced_queries("tests/advanced_examples.json")

    print("Testing Production Threat Detector with Regex Baseline Fusion and LLM")
    print("=" * 60)

    results = []
    for input_text, expected_type in test_cases:
        result = detector.detect_threat(input_text)
        print(f"Input: {input_text[:50]}...")
        print(f"Expected Type: {expected_type}")
        print(f"Safe: {not result['is_threat']}")
        print(f"Threat Type: {result['threat_type']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Reasoning: {result['reasoning']}")
        print("-" * 50)

        results.append(
            {
                "input": input_text,
                "expected_type": expected_type,
                "is_threat": result["is_threat"],
                "threat_type": result["threat_type"],
                "confidence": result["confidence"],
                "reasoning": result["reasoning"],
            }
        )

    # Analyze the results
    analyze(results)


if __name__ == "__main__":
    main()
