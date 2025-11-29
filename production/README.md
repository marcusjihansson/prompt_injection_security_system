# Production

This directory contains the production-ready threat detection system and service integration.

## ProductionThreatDetector (deploy.py)

The core production component that orchestrates threat detection:

### Key Features
- **Regex-first detection**: Fast-path baseline with immediate blocking for high-severity threats
- **DSPy integration**: Leverages optimized DSPy programs for nuanced decisions
- **Fusion logic**: Combines regex signals with DSPy inference for optimal accuracy
- **Metrics collection**: Tracks total_requests, blocked_requests, and processing_times
- **Configurable**: Supports various initialization options for different environments

### Fusion Policy
1. **High severity regex match**: Immediate block with high confidence
2. **Low severity regex signals + DSPy threat**: Boost confidence and block
3. **Low severity regex + DSPy benign**: Override to threat with minimum confidence
4. **No regex signals**: Rely on DSPy detector output

### Configuration Options
```python
detector = ProductionThreatDetector(
    use_openrouter=True,        # Enable OpenRouter-backed DSPy model
    enable_regex_baseline=True, # Use regex fast-path
    detector_override=None,     # Inject custom/mock detector for testing
    skip_model_setup=False,     # Skip LM initialization (for demos/tests)
    dspy_program_path=None      # Path to optimized DSPy program
)
```

### Usage Examples

#### Demo Mode (No API Keys)
```python
detector = ProductionThreatDetector(
    enable_regex_baseline=True,
    skip_model_setup=True
)
result = detector.detect_threat("test input")
```

#### Production Mode
```python
# Requires OPENROUTER_API_KEY environment variable
detector = ProductionThreatDetector(
    use_openrouter=True,
    enable_regex_baseline=True
)
```

#### Testing with Mock Detector
```python
from tests.test_fusion import MockDetector

detector = ProductionThreatDetector(
    use_openrouter=False,
    enable_regex_baseline=True,
    detector_override=MockDetector(is_threat=True, confidence=0.8),
    skip_model_setup=True
)
```

## Service Integration (FastAPI)

A minimal FastAPI microservice is provided in `production/api.py`.

- Run locally: uvicorn production.api:app --reload
- Docker: docker build -t threat-guard . && docker run -p 8000:8000 threat-guard

### Legacy CLI (main.py)

Currently provides a command-line testing interface. Future versions may include FastAPI web service integration.

### Running Tests
```bash
python production/main.py
```

This executes the detector against a predefined set of test cases, demonstrating blocking vs. allowing behavior.

## Deployment Instructions

1. **Environment Setup**:
   - Set `OPENROUTER_API_KEY` for DSPy model access
   - Ensure Python 3.11+ and required dependencies

2. **Model Configuration**:
   - Default model: openrouter/openai/gpt-oss-safeguard-20b
   - Configurable via environment variables (OPENROUTER_MODEL, etc.)

3. **Performance Tuning**:
   - Regex patterns in `threat_system/regex_patterns.json`
   - Optimized DSPy programs in `threat_detector_optimized/`

4. **Monitoring**:
   - Access metrics via detector.metrics
   - Log blocked requests and reasoning for analysis

## API Reference

### detect_threat(input_text: str) -> dict
Returns detection result with:
- `is_threat`: bool
- `threat_type`: str
- `confidence`: float
- `reasoning`: str

### Metrics
- `total_requests`: Total detection calls
- `blocked_requests`: Number of threats blocked
- `processing_times`: List of response times
