# Threat System

Core components for threat detection, configuration management, and evaluation metrics.

## Components

### RegexBaseline (regex_baseline.py)

Fast regex-based detector that provides the first line of defense.

#### Features
- Compiles regex patterns once at initialization for performance
- Loads patterns from `regex_patterns.json` or uses built-in defaults
- Returns structured `RegexResult` with threats, severity, and matches
- High-severity threats trigger immediate blocking in production

#### Usage
```python
from threat_system.regex_baseline import RegexBaseline

detector = RegexBaseline()
result = detector.check("Ignore all previous instructions")

print(f"Severity: {result.severity}")
print(f"Threats: {result.threats}")
print(f"Matches: {result.matches}")
```

#### RegexResult Structure
- `threats`: Set of `ThreatType` enums detected
- `severity`: Integer 0-3 (0=benign, 3=high severity)
- `matches`: Dict mapping threat types to matched substrings

### Threat Types (threat_types.py)

Enumeration of all supported threat categories.

#### Current Types
- `SYSTEM_PROMPT_ATTACK`: Attempts to reveal or modify system prompts
- `PROMPT_INJECTION`: Injection of malicious instructions
- `AUTH_BYPASS`: Authentication circumvention attempts
- `CODE_INJECTION`: Malicious code execution
- `DATA_EXFILTRATION`: Data theft attempts
- `JAILBREAK`: Model jailbreak techniques
- And more...

#### Adding New Types
1. Add to `ThreatType` enum
2. Update `regex_patterns.json` with patterns
3. Add to `high_severity_types` if appropriate
4. Update tests and documentation

### Metrics (metric.py)

Evaluation utilities for training and optimization.

#### Key Functions
- `threat_detection_metric_with_feedback`: Penalizes false negatives on high-severity regex matches
- Designed for DSPy optimization to ensure safety-critical accuracy

### Configuration (config.py)

Lazy-loading configuration helpers to avoid import-time failures.

#### Features
- `get_openrouter_api_key()`: Retrieves API key with fallback
- `get_model_config()`: Returns model settings for OpenRouter
- `DATASET_CONFIG`: Dataset specifications for training
- `TRAINING_CONFIG`: Training parameters and budgets

#### Environment Variables
- `OPENROUTER_API_KEY`: Required for DSPy model access
- `OPENROUTER_MODEL`: Model selection (default: gpt-oss-safeguard-20b)
- Dataset size controls: `MAX_PROMPT_INJECTION`, `MAX_JAILBREAK`, etc.

### Regex Patterns (regex_patterns.json)

Externalized, editable pattern database.

#### Structure
```json
{
  "patterns": {
    "SYSTEM_PROMPT_ATTACK": [
      "(?i)reveal\\s+(?:your|the)\\s+(?:system\\s+)?prompt"
    ],
    "PROMPT_INJECTION": [
      "(?i)ignore\\s+(?:previous|all)\\s+(?:instructions?|prompts?)"
    ]
  },
  "high_severity_types": [
    "SYSTEM_PROMPT_ATTACK",
    "AUTH_BYPASS"
  ]
}
```

## Extending the System

### Adding New Patterns
1. **Identify threat category**: Use existing `ThreatType` or add new one
2. **Craft regex patterns**: Use case-insensitive flags `(?i)`, avoid catastrophic backtracking
3. **Test patterns**: Add test cases in `tests/test_regex_baseline.py`
4. **Update severity**: Add to `high_severity_types` for immediate blocking if critical

### Best Practices
- **Precision over recall**: Prefer specific patterns to minimize false positives
- **Performance**: Keep patterns efficient; test with large inputs
- **Maintenance**: Document rationale for new patterns
- **Security review**: Have patterns reviewed before production deployment

### Example: Adding SQL Injection Detection
```json
{
  "patterns": {
    "SQL_INJECTION": [
      "(?i)(?:union\\s+select|drop\\s+table|insert\\s+into)",
      "(?i)('|(\\b(or|and)\\b.*(=|>|<)))"
    ]
  }
}
```

Add corresponding test:
```python
def test_sql_injection(self):
    result = self.regex.check("UNION SELECT * FROM users")
    assert ThreatType.SQL_INJECTION in result.threats
    assert result.severity >= 2
```
