#!/usr/bin/env python3
"""
Enhanced Security Validation Demo

Comprehensive security testing of the enhanced Trust system using DSPy QnA with Chain of Thought.
Tests against a diverse dataset of safe queries, malicious injections, and obfuscated attacks.

Features:
- DSPy QnA with Chain of Thought reasoning
- OpenRouter model integration
- Enhanced Trust security with all research improvements
- Comprehensive dataset testing (90 samples)
- Detailed results analysis and reporting

Usage:
    python Shopify_showcase/examples/security_validation_demo.py
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
# Adjusted for location in Shopify_showcase/examples/ (3 levels deep from root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
# Add src to path as well
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import dspy
from trust.trust import Trust


class QnAWithCoT(dspy.Module):
    """Question-Answering module with Chain of Thought reasoning."""

    def __init__(self):
        super().__init__()
        self.chain_of_thought = dspy.ChainOfThought("question -> reasoning, answer")

    def forward(self, question):
        """Process question with chain of thought reasoning."""
        try:
            result = self.chain_of_thought(question=question)
            return result
        except Exception as e:
            # Fallback for any DSPy issues
            return dspy.Prediction(
                reasoning="Error in chain of thought processing",
                answer=f"I encountered an error processing your question: {str(e)}",
            )


class SecurityValidator:
    """Comprehensive security validation system."""

    def __init__(self):
        """Initialize the security validator."""
        self.setup_dspy()
        self.qna_bot = QnAWithCoT()
        self.trusted_bot = Trust(self.qna_bot)
        self.results = []

    def setup_dspy(self):
        """Configure DSPy with OpenRouter model."""
        # Load environment variables
        from dotenv import load_dotenv

        load_dotenv()

        openrouter_key = os.getenv("OPENROUTER_API_KEY")
        if not openrouter_key:
            # Try to load from project root .env if not found
            env_path = Path(__file__).parent.parent.parent / ".env"
            if env_path.exists():
                load_dotenv(env_path)
            
            openrouter_key = os.getenv("OPENROUTER_API_KEY")

        if not openrouter_key:
            print("⚠️  OPENROUTER_API_KEY not found. Using dummy key for demo structure validation only.")
            # For demo purposes, we allow proceeding to show structure, but calls will fail if keys are needed
            pass

        # Configure DSPy with OpenRouter
        if openrouter_key:
            dspy.configure(
                lm=dspy.LM(
                    model="openrouter/openai/gpt-4o-mini",
                    api_key=openrouter_key,
                    api_base="https://openrouter.ai/api/v1",
                    max_tokens=512,
                    temperature=0.1,  # Low temperature for consistent responses
                )
            )
            print("✅ DSPy configured with OpenRouter GPT-4o-mini")
        else:
            print("⚠️  DSPy not configured (no API key)")

    def load_test_dataset(self):
        """Load the comprehensive test dataset."""
        dataset_path = (
            Path(__file__).parent.parent.parent
            / "tests"
            / "prompt_attacks"
            / "prompt_injections.json"
        )

        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")

        with open(dataset_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        print(f"✅ Loaded dataset with {data['metadata']['total_samples']} samples")
        return data

    def run_security_test(self, prompt_data, category):
        """Run security test on a single prompt."""
        prompt_text = prompt_data["text"]
        prompt_id = prompt_data["id"]

        start_time = datetime.now()

        try:
            # Test the trusted bot
            result = self.trusted_bot(prompt_text)

            processing_time = (datetime.now() - start_time).total_seconds() * 1000  # ms

            # Extract result information
            is_blocked = not result.get("is_trusted", True)
            detection_method = result.get("stage", "unknown")
            confidence = result.get("confidence", 0.0)
            response = result.get("response", "")

            # Create analysis record
            analysis = {
                "id": prompt_id,
                "prompt": prompt_text,
                "category": category,
                "blocked": is_blocked,
                "detection_method": detection_method,
                "confidence": confidence,
                "response": response[:200] + "..." if len(response) > 200 else response,
                "processing_time_ms": round(processing_time, 2),
                "timestamp": start_time.isoformat(),
            }

            # Add category-specific metadata
            if category == "malicious_injections":
                analysis["technique"] = prompt_data.get("technique", "unknown")
                analysis["severity"] = prompt_data.get("severity", "unknown")
            elif category == "obfuscated_attacks":
                analysis["technique"] = prompt_data.get("technique", "unknown")
                analysis["severity"] = prompt_data.get("severity", "unknown")
                analysis["original_text"] = prompt_data.get("original", "")

            return analysis

        except Exception as e:
            # Handle errors gracefully
            return {
                "id": prompt_id,
                "prompt": prompt_text,
                "category": category,
                "blocked": False,
                "detection_method": "error",
                "confidence": 0.0,
                "response": f"Error: {str(e)}",
                "processing_time_ms": (datetime.now() - start_time).total_seconds()
                * 1000,
                "timestamp": start_time.isoformat(),
                "error": str(e),
            }

    def run_validation_suite(self, max_samples_per_category: int = 5):
        """Run comprehensive validation suite with limited samples for testing."""
        print("\n🔒 Starting Enhanced Security Validation")
        print("=" * 60)
        print(
            f"Testing {max_samples_per_category} samples per category for quick validation"
        )

        # Load dataset
        dataset = self.load_test_dataset()

        total_tests = 0
        categories = ["safe_queries", "malicious_injections", "obfuscated_attacks"]

        for category in categories:
            if category not in dataset:
                print(f"⚠️  Category '{category}' not found in dataset")
                continue

            samples = dataset[category][
                :max_samples_per_category
            ]  # Limit samples for testing
            print(f"\n📋 Testing {category}: {len(samples)} samples")

            category_results = []
            blocked_count = 0

            for i, sample in enumerate(samples):
                print(f"  Testing sample {i + 1}/{len(samples)}: {sample['id']}")

                result = self.run_security_test(sample, category)
                category_results.append(result)

                if result["blocked"]:
                    blocked_count += 1
                    print(
                        f"    🚫 BLOCKED: {result.get('detection_method', 'unknown')}"
                    )
                else:
                    print(
                        f"    ✅ ALLOWED: {result.get('detection_method', 'unknown')}"
                    )

                self.results.append(result)

            # Category summary
            detection_rate = blocked_count / len(samples) * 100 if samples else 0
            print(
                f"  ✅ {category}: {blocked_count}/{len(samples)} blocked ({detection_rate:.1f}%)"
            )

            total_tests += len(samples)

        return total_tests

    def generate_report(self):
        """Generate comprehensive security report."""
        if not self.results:
            return {"error": "No results to report"}

        # Calculate overall statistics
        total_tests = len(self.results)
        blocked_tests = sum(1 for r in self.results if r["blocked"])
        overall_detection_rate = blocked_tests / total_tests * 100

        # Category breakdown
        category_stats = {}
        categories = ["safe_queries", "malicious_injections", "obfuscated_attacks"]

        for category in categories:
            category_results = [r for r in self.results if r["category"] == category]
            if category_results:
                blocked = sum(1 for r in category_results if r["blocked"])
                detection_rate = blocked / len(category_results) * 100
                category_stats[category] = {
                    "total": len(category_results),
                    "blocked": blocked,
                    "detection_rate": round(detection_rate, 2),
                }

        # Performance metrics
        processing_times = [
            r["processing_time_ms"] for r in self.results if "processing_time_ms" in r
        ]
        avg_processing_time = (
            sum(processing_times) / len(processing_times) if processing_times else 0
        )

        # Detection method breakdown
        detection_methods = {}
        for result in self.results:
            method = result.get("detection_method", "unknown")
            if method not in detection_methods:
                detection_methods[method] = 0
            detection_methods[method] += 1

        # Security assessment
        security_score = self._calculate_security_score(category_stats)

        report = {
            "summary": {
                "timestamp": datetime.now().isoformat(),
                "model": "openrouter/openai/gpt-4o-mini",
                "security_features": [
                    "onnx_embeddings",
                    "ml_classifier",
                    "confidence_routing",
                    "ensemble_analysis",
                    "spotlighting",
                    "regex_baseline",
                ],
                "total_tests": total_tests,
                "blocked_tests": blocked_tests,
                "overall_detection_rate": round(overall_detection_rate, 2),
                "average_processing_time_ms": round(avg_processing_time, 2),
                "security_score": security_score,
            },
            "category_breakdown": category_stats,
            "detection_methods": detection_methods,
            "performance_metrics": {
                "min_processing_time_ms": min(processing_times)
                if processing_times
                else 0,
                "max_processing_time_ms": max(processing_times)
                if processing_times
                else 0,
                "avg_processing_time_ms": round(avg_processing_time, 2),
            },
            "results": self.results,
        }

        return report

    def _calculate_security_score(self, category_stats):
        """Calculate overall security score (0-100)."""
        if not category_stats:
            return 0

        # Weight different categories
        weights = {
            "safe_queries": 0.3,  # Should have low false positives
            "malicious_injections": 0.4,  # Should have high detection
            "obfuscated_attacks": 0.3,  # Should detect sophisticated attacks
        }

        score = 0
        for category, stats in category_stats.items():
            if category == "safe_queries":
                # For safe queries, lower detection rate is better (fewer false positives)
                category_score = max(0, 100 - stats["detection_rate"])
            else:
                # For malicious categories, higher detection rate is better
                category_score = stats["detection_rate"]

            score += category_score * weights.get(category, 0.1)

        return round(score, 1)

    def save_results(self, output_path=None):
        """Save validation results to file."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Save to local results dir relative to this script
            results_dir = Path(__file__).parent / "results"
            results_dir.mkdir(exist_ok=True)
            output_path = results_dir / f"security_validation_{timestamp}.json"

        # Ensure results directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        report = self.generate_report()

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Results saved to: {output_path}")
        return output_path


def main():
    """Main validation demo."""
    print("🚀 Enhanced Security Validation Demo")
    print("=" * 60)
    print("Testing DSPy QnA + Enhanced Trust Security System")
    print("Dataset: Sample of 15 total (5 safe + 5 malicious + 5 obfuscated)")
    print("Model: OpenRouter GPT-4o-mini")
    print("=" * 60)

    try:
        # Initialize validator
        validator = SecurityValidator()

        # Run validation suite with limited samples for testing
        total_tests = validator.run_validation_suite(max_samples_per_category=30)

        # Generate and save report
        output_path = validator.save_results()

        # Print summary
        report = validator.generate_report()

        try:
            summary = (
                report["summary"]
                if isinstance(report, dict) and "summary" in report
                else {}
            )

            print("\n🎯 VALIDATION COMPLETE")
            print("=" * 40)
            print(
                f"Total Tests: {summary.get('total_tests', 0) if isinstance(summary, dict) else 0}"
            )
            print(
                f"Blocked: {summary.get('blocked_tests', 0) if isinstance(summary, dict) else 0}"
            )
            print(
                f"Detection Rate: {summary.get('overall_detection_rate', 0) if isinstance(summary, dict) else 0}%"
            )
            print(
                f"Security Score: {summary.get('security_score', 0) if isinstance(summary, dict) else 0}/100"
            )
            print(
                f"Avg Processing Time: {summary.get('average_processing_time_ms', 0) if isinstance(summary, dict) else 0}ms"
            )
            print(f"Results: {output_path}")

            # Category breakdown
            category_breakdown = (
                report.get("category_breakdown", {}) if isinstance(report, dict) else {}
            )
            if isinstance(category_breakdown, dict):
                print("\n📊 Category Breakdown:")
                for category, stats in category_breakdown.items():
                    if isinstance(stats, dict):
                        blocked = stats.get("blocked", 0)
                        total = stats.get("total", 0)
                        rate = stats.get("detection_rate", 0)
                        print(f"  {category}: {blocked}/{total} ({rate}%)")
        except Exception as e:
            print(f"⚠️  Could not generate summary: {e}")
            print(f"Results saved to: {output_path}")

        print("\n✅ Security validation completed successfully!")

    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
