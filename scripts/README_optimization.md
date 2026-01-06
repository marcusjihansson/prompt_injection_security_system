# ThreatDetector Optimization Script

This script pre-optimizes the ThreatDetector using GEPA (Generative Program Optimization) training to create faster, more accurate threat detection models.

## Quick Start

1. **Set your API key:**
   ```bash
   export OPENROUTER_API_KEY=your_openrouter_api_key
   # OR add it to your .env file
   ```

2. **Run the optimization:**
   ```bash
   python scripts/optimize_detector.py
   ```

## What It Does

- Downloads threat detection datasets (prompt injections, jailbreaks)
- Trains an optimized DSPy program using GEPA
- Saves the optimized model to `threat_detector_optimized/`
- The system automatically uses optimized models on next startup

## Configuration

Adjust training parameters in your `.env` file:

```bash
# Number of training examples
MAX_PROMPT_INJECTION=50
MAX_JAILBREAK=50

# Training budget
# Options: 'light', 'medium', 'heavy'
# Light: Faster training, good for testing
# Heavy: Better accuracy, longer training
```

## Expected Output

```
ThreatDetector Pre-Optimization Script
==================================================
Checking system resources...
   Available RAM: 16.0 GB
Starting GEPA optimization...
📚 Running optimization (this may take several minutes)...
Optimization completed successfully!
Optimized models saved to: threat_detector_optimized/
🔄 The system will now use these optimized models automatically
```

## Troubleshooting

- **API Key Issues**: Ensure OPENROUTER_API_KEY is set and valid
- **Memory Issues**: Reduce MAX_PROMPT_INJECTION/MAX_JAILBREAK for lower RAM usage
- **Timeout Issues**: Check internet connection stability

## Advanced Usage

For custom optimization:

```python
from src.trust.optimizer.train_gepa import run_gepa_optimization

# Custom training with specific iterations
detector = run_gepa_optimization(max_iterations=100)
```

The optimized models provide significant performance improvements while maintaining high accuracy for threat detection.</content>
<parameter name="filePath">scripts/README_optimization.md