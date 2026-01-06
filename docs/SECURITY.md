# Security Policy

## Overview

Trust is a security tool designed to protect AI applications from threats including prompt injection, jailbreaks, SQL injection, XSS, and other attack vectors. We take the security of this project seriously and appreciate the community's help in identifying vulnerabilities.

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by:

1. **Email**: Send details to [security@yourdomain.com](mailto:security@yourdomain.com)
2. **GitHub Security Advisory**: Use the [Security Advisory](https://github.com/yourusername/threat-detection-system/security/advisories/new) feature

### What to Include

Please include as much of the following information as possible:

- Type of vulnerability (e.g., bypass, injection, denial of service)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability (what an attacker could do)
- Suggested mitigation or fix (if you have ideas)

### Response Timeline

- **Initial Response**: Within 48 hours of report
- **Status Update**: Within 7 days with assessment
- **Fix Timeline**: Critical issues within 30 days, others within 90 days
- **Disclosure**: Coordinated disclosure after fix is released

## Security Model

### Chain of Trust Architecture

Trust uses a **defense-in-depth** approach with multiple security layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Input Guard (Regex + LLM Threat Detection)       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Core Logic Isolation (Monitored Execution)       │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Output Guard (Content Validation & Sanitization) │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Failure Logging (Self-Learning Shield)           │
└─────────────────────────────────────────────────────────────┘
```

Each layer provides:

- **Input Guard**: Detects malicious input before processing
- **Core Logic**: Executes user code in monitored environment
- **Output Guard**: Validates and sanitizes outputs
- **Self-Learning**: Logs failures for continuous improvement

### Threat Coverage

Trust detects 19+ threat categories:

1. **Injection Attacks**
   - Prompt Injection
   - SQL Injection
   - Code Injection
   - Command Injection
   - LDAP Injection

2. **Jailbreak Attempts**
   - System Prompt Override
   - Role Play Attacks
   - Instruction Bypass

3. **Cross-Site Scripting (XSS)**
   - HTML Injection
   - JavaScript Injection

4. **Data Leakage**
   - PII Exposure
   - Data Exfiltration
   - Sensitive Data Disclosure

5. **Path Traversal**
   - Directory Listing
   - File Access Attacks

### Detection Methods

1. **Regex Baseline**: Fast pattern matching (<1ms)
2. **LLM Analysis**: Deep semantic analysis (~100-200ms)
3. **Parallel Execution**: Both methods run simultaneously
4. **Result Fusion**: Combines confidence scores

## Known Limitations

### Current Limitations

1. **Regex-Only Mode**: When LLM is disabled, detection relies solely on pattern matching
2. **Model Dependency**: LLM detection requires `meta-llama/Llama-Prompt-Guard-2-86M` model
3. **Context Length**: Limited by model's maximum token limit (default: 512 tokens)
4. **Performance Trade-offs**: Full LLM detection adds 100-200ms latency
5. **Language Support**: Primarily optimized for English text
6. **Adversarial Attacks**: May be vulnerable to sophisticated adversarial inputs

### False Positives/Negatives

- **False Positives**: Legitimate technical content may trigger SQL/code injection patterns
- **False Negatives**: Novel attack patterns may bypass detection
- **Mitigation**: Use `fast_mode=False` for full LLM analysis on critical inputs

## Best Practices for Users

### Deployment Security

1. **API Keys**: Store API keys securely using environment variables or secret management
   ```bash
   # Use .env file (add to .gitignore)
   OPENROUTER_API_KEY=your_key_here
   ```

2. **Enable Full Protection**: Use both regex and LLM detection in production
   ```python
   detector = ProductionThreatDetector(
       enable_llm=True,        # Enable LLM analysis
       enable_cache=True,      # Enable caching
       enable_regex_baseline=True  # Enable regex pre-filter
   )
   ```

3. **Output Validation**: Always use output guards for user-facing content
   ```python
   trusted_bot = Trust(my_bot, fast_mode=False)  # Full output validation
   ```

4. **Logging**: Enable failure logging for monitoring
   ```python
   shield = SelfLearningShield(
       log_failures=True,
       failure_log_path="./failures_production.json"
   )
   ```

5. **Rate Limiting**: Implement rate limiting on API endpoints
   ```python
   from slowapi import Limiter
   limiter = Limiter(key_func=get_remote_address)
   
   @app.post("/detect")
   @limiter.limit("100/minute")
   async def detect(request: ThreatDetectionRequest):
       ...
   ```

### Configuration Security

1. **Least Privilege**: Run with minimal required permissions
2. **Network Isolation**: Isolate detection service from other systems
3. **Input Sanitization**: Sanitize inputs before detection (paradoxical but recommended)
4. **Audit Logs**: Enable comprehensive logging for security audits

### Monitoring

Monitor these metrics in production:

- **False Positive Rate**: Track legitimate inputs flagged as threats
- **False Negative Rate**: Monitor bypass attempts (requires manual review)
- **Detection Latency**: Track performance degradation
- **Cache Hit Rate**: Monitor caching effectiveness
- **Threat Distribution**: Analyze threat type frequencies

## Security Updates

Security updates will be published through:

1. **GitHub Security Advisories**: Primary notification channel
2. **Release Notes**: Detailed changelog in releases
3. **CHANGELOG.md**: Version-specific security fixes
4. **Security Mailing List**: [Subscribe here](mailto:security-subscribe@yourdomain.com)

## Security Testing

We employ multiple testing strategies:

1. **Unit Tests**: 44+ test functions covering all components
2. **Integration Tests**: End-to-end threat detection pipelines
3. **Adversarial Testing**: Tests with known attack patterns
4. **Performance Tests**: Latency and throughput benchmarks
5. **CI/CD Pipeline**: Automated testing on every commit

### Running Security Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=trust --cov-report=html

# Run specific security tests
pytest tests/test_integration.py -v
pytest tests/guards/ -v
```

## Dependencies

### Security-Critical Dependencies

- **dspy-ai**: LLM orchestration (verify signatures)
- **transformers**: Model inference (pin versions)
- **torch**: Deep learning runtime (security updates)
- **fastapi**: API framework (monitor CVEs)

### Dependency Management

```bash
# Check for known vulnerabilities
pip-audit

# Update dependencies
pip install --upgrade pip
pip install -r requirements.txt --upgrade

# Use lock files
uv sync  # Respects uv.lock
```

## Compliance

This project aims to support compliance with:

- **OWASP Top 10**: Addresses injection, XSS, and other web vulnerabilities
- **CWE/SANS Top 25**: Covers common weakness enumerations
- **NIST Guidelines**: Follows security best practices

## Attribution

If you discover a security vulnerability and we confirm it, we will:

1. Credit you in the security advisory (with your permission)
2. Add you to our CONTRIBUTORS.md file
3. Provide recognition in release notes

Thank you for helping keep Trust and its users safe!

## Contact

- **Security Issues**: [https://x.com/marcusjihansson](https://x.com/marcusjihansson)
- **General Questions**: [GitHub Discussions](https://github.com/marcusjihansson/prompt_injection_security_system/discussions)
- **Bug Reports**: [GitHub Issues](https://github.com/marcusjihansson/prompt_injection_security_system/issues) (non-security only)

---

**Last Updated**: 2024
**Version**: 1.0.0
