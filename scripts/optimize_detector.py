#!/usr/bin/env python3
"""
Script to pre-optimize the ThreatDetector using GEPA training.

This script runs the GEPA optimization process to create optimized DSPy programs
for threat detection, which are then saved to threat_detector_optimized/ directory.

Usage:
    python scripts/optimize_detector.py

Requirements:
    - OPENROUTER_API_KEY environment variable set
    - Sufficient system resources (RAM, disk space)

The optimization process may take several minutes to hours depending on:
    - Number of training examples
    - Model size and complexity
    - System performance
"""

import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def main():
    """Run the ThreatDetector optimization process."""
    print("🚀 ThreatDetector Pre-Optimization Script")
    print("=" * 50)

    # Check for API key
    if not os.getenv("OPENROUTER_API_KEY"):
        print("❌ ERROR: OPENROUTER_API_KEY environment variable not set")
        print("   Please set your OpenRouter API key:")
        print("   export OPENROUTER_API_KEY=your_key_here")
        print("   Or add it to your .env file")
        return 1

    # Check system resources
    print("🔍 Checking system resources...")
    try:
        import psutil

        memory_gb = psutil.virtual_memory().total / (1024**3)
        print(f"   Available RAM: {memory_gb:.1f} GB")

        if memory_gb < 8:
            print("⚠️  WARNING: Low memory detected. Training may be slow or fail.")
            print("   Recommended: 16GB+ RAM for optimal performance")
    except ImportError:
        print("ℹ️  Could not check system resources (psutil not installed)")

    # Import and run optimization
    try:
        print("\n🔧 Starting GEPA optimization...")
        from trust.optimizer.train_gepa import (
            run_gepa_optimization,
            test_optimized_detector,
        )

        # Run optimization with light budget for faster completion
        print("📚 Running optimization (this may take several minutes)...")
        optimized_detector = run_gepa_optimization(
            max_iterations=50
        )  # Limit iterations for demo

        print("\n🧪 Testing optimized detector...")
        test_optimized_detector(optimized_detector)

        print("\n✅ Optimization completed successfully!")
        print("📁 Optimized models saved to: threat_detector_optimized/")
        print("🔄 The system will now use these optimized models automatically")

        return 0

    except Exception as e:
        print(f"\n❌ ERROR during optimization: {e}")
        print("\nTroubleshooting tips:")
        print("1. Check your OPENROUTER_API_KEY is valid")
        print("2. Ensure stable internet connection")
        print("3. Check system has sufficient RAM (>8GB recommended)")
        print("4. Try reducing MAX_PROMPT_INJECTION and MAX_JAILBREAK in .env")
        return 1


if __name__ == "__main__":
    sys.exit(main())
