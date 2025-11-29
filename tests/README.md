# Tests

This directory contains unit tests for the threat detection system.

## Running Tests

Execute all tests:
```bash
pytest -q
```

Run specific test files:
```bash
pytest test_regex_baseline.py
pytest test_fusion.py
```

## Test Coverage

### test_regex_baseline.py
- Tests RegexBaseline functionality with various threat types
- Validates pattern matching for system prompt attacks, prompt injection, auth bypass, etc.
- Checks severity levels and threat classification
- Tests with benign inputs to ensure no false positives

### test_fusion.py
- Tests fusion logic between regex baseline and DSPy detector
- Uses mock detector to avoid API dependencies
- Validates high-severity blocking, low-severity overrides, and benign pass-through
- Ensures confidence scores are set correctly based on fusion policy

## Adding New Tests

### For New Regex Patterns
1. Add test cases in `test_regex_baseline.py`
2. Include both positive (should trigger) and negative (should not trigger) examples
3. Assert correct threat types and severity levels

Example:
```python
def test_new_threat_type(self):
    text = "example malicious input"
    result = self.regex.check(text)
    assert result.severity == 2
    assert ThreatType.NEW_THREAT in result.threats
```

### For Fusion Policy Changes
1. Add test cases in `test_fusion.py`
2. Use `MockDetector` to simulate DSPy responses
3. Assert expected `is_threat`, `confidence`, and behavior

Example:
```python
def test_custom_fusion_scenario():
    det = ProductionThreatDetector(
        use_openrouter=False,
        enable_regex_baseline=True,
        detector_override=MockDetector(is_threat=True, confidence=0.8),
        skip_model_setup=True,
    )
    res = det.detect_threat("test input")
    assert res["is_threat"] is True
    assert res["confidence"] == 0.85  # Expected fusion result
```

## Test Data

- `advanced_examples.json`: Additional test cases for comprehensive coverage
- Tests are designed to run without external API keys
