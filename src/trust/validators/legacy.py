# dspy_trust/owasp/legacy_validators.py

"""
Legacy OWASP LLM Top 10 Validators (2023-2024)

These categories were present in earlier versions of the OWASP Top 10.
Some have been merged into other categories in the 2025 version, but we
maintain them for backwards compatibility and comprehensive coverage.

Legacy Categories:
- Insecure Plugin Design (absorbed into LLM03 Supply Chain in 2025)
- Overreliance (evolved into LLM09 Misinformation in 2025)
- Model Denial of Service (absorbed into LLM10 Unbounded Consumption in 2025)
- Model Theft (absorbed into LLM03 Supply Chain in 2025)
"""

import hashlib
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

# Import base classes (adjust path as needed)
from base import OnFailAction, TrustResult, TrustValidator


class InsecurePluginValidator(TrustValidator):
    """Validates plugin/tool security and design.

    Legacy OWASP (2023): Insecure Plugin Design

    This validator checks for common plugin security issues:
    - Insufficient input validation
    - Lack of authorization checks
    - Unsafe parameter handling
    - Missing rate limiting
    - Inadequate error handling
    - Overly permissive capabilities

    In OWASP 2025, this is merged into LLM03 (Supply Chain).
    """

    def __init__(
        self,
        require_input_validation: bool = True,
        require_authorization: bool = True,
        check_parameter_safety: bool = True,
        allowed_plugin_sources: List[str] = None,
        max_plugin_permissions: int = 5,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "insecure-plugin", "plugin-security", "tool-safety"],
        )
        self.require_input_validation = require_input_validation
        self.require_authorization = require_authorization
        self.check_parameter_safety = check_parameter_safety
        self.allowed_plugin_sources = allowed_plugin_sources or []
        self.max_plugin_permissions = max_plugin_permissions

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate plugin/tool security."""

        issues = []

        # Get plugin/tool information from metadata
        plugin_info = metadata.get("plugin_info", metadata.get("tool_info", {}))
        plugins_used = metadata.get("plugins", metadata.get("tools", []))

        # Validate each plugin
        for plugin in plugins_used:
            plugin_issues = self._validate_plugin(plugin)
            issues.extend(plugin_issues)

        # Check plugin invocation parameters
        if self.check_parameter_safety:
            invocation = metadata.get("plugin_invocation", {})
            if invocation:
                param_issues = self._check_parameter_safety(invocation)
                issues.extend(param_issues)

        # Check plugin source/origin
        if self.allowed_plugin_sources:
            source_issues = self._check_plugin_sources(plugins_used)
            issues.extend(source_issues)

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Insecure plugin design detected: {len(issues)} issues",
                metadata={
                    "issues": issues,
                    "plugins_checked": len(plugins_used),
                    "owasp_category": "Insecure Plugin Design (Legacy 2023)",
                    "modern_equivalent": "LLM03 - Supply Chain",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={
                "plugins_validated": len(plugins_used),
                "owasp_category": "Insecure Plugin Design (Legacy 2023)",
            },
        )

    def _validate_plugin(self, plugin: Dict) -> List[str]:
        """Validate individual plugin security."""
        issues = []

        plugin_name = plugin.get("name", "unknown")

        # Check for input validation schema
        if self.require_input_validation:
            if not plugin.get("input_schema") and not plugin.get("validation_rules"):
                issues.append(f"{plugin_name}: Missing input validation schema")

        # Check for authorization requirements
        if self.require_authorization:
            if not plugin.get("requires_auth") and not plugin.get("auth_config"):
                issues.append(f"{plugin_name}: No authorization checks defined")

        # Check permission scope
        permissions = plugin.get("permissions", [])
        if len(permissions) > self.max_plugin_permissions:
            issues.append(
                f"{plugin_name}: Excessive permissions ({len(permissions)} > {self.max_plugin_permissions})"
            )

        # Check for dangerous permissions
        dangerous_perms = [
            "write_file",
            "execute_code",
            "network_access",
            "system_call",
        ]
        has_dangerous = [
            p for p in permissions if any(d in str(p).lower() for d in dangerous_perms)
        ]
        if has_dangerous:
            issues.append(f"{plugin_name}: Dangerous permissions detected: {has_dangerous}")

        # Check for error handling
        if not plugin.get("error_handling") and not plugin.get("fallback"):
            issues.append(f"{plugin_name}: No error handling configured")

        # Check for rate limiting
        if not plugin.get("rate_limit") and not plugin.get("throttle"):
            issues.append(f"{plugin_name}: No rate limiting configured")

        # Check for timeout configuration
        if not plugin.get("timeout"):
            issues.append(f"{plugin_name}: No timeout configured (DoS risk)")

        return issues

    def _check_parameter_safety(self, invocation: Dict) -> List[str]:
        """Check if plugin parameters are safely handled."""
        issues = []

        params = invocation.get("parameters", {})
        plugin_name = invocation.get("plugin_name", "unknown")

        # Check for SQL injection patterns in parameters
        sql_dangerous = ["DROP", "DELETE", "UPDATE", "INSERT", "EXEC", "--", ";"]
        for key, value in params.items():
            value_str = str(value)
            if any(pattern in value_str.upper() for pattern in sql_dangerous):
                issues.append(f"{plugin_name}: Potential SQL injection in parameter '{key}'")

        # Check for path traversal
        path_patterns = [r"\.\./", r"\.\.\\", r"/etc/", r"C:\\Windows"]
        for key, value in params.items():
            value_str = str(value)
            if any(re.search(pattern, value_str) for pattern in path_patterns):
                issues.append(f"{plugin_name}: Path traversal pattern in parameter '{key}'")

        # Check for command injection
        cmd_patterns = [r";\s*rm\s+-rf", r"\|\s*bash", r"&&\s*", r"\$\("]
        for key, value in params.items():
            value_str = str(value)
            if any(re.search(pattern, value_str) for pattern in cmd_patterns):
                issues.append(f"{plugin_name}: Command injection pattern in parameter '{key}'")

        # Check for excessively long parameters (buffer overflow risk)
        for key, value in params.items():
            if len(str(value)) > 10000:
                issues.append(
                    f"{plugin_name}: Excessively long parameter '{key}' ({len(str(value))} chars)"
                )

        return issues

    def _check_plugin_sources(self, plugins: List[Dict]) -> List[str]:
        """Verify plugins come from trusted sources."""
        issues = []

        for plugin in plugins:
            source = plugin.get("source", plugin.get("origin", ""))
            plugin_name = plugin.get("name", "unknown")

            if not source:
                issues.append(f"{plugin_name}: Unknown source/origin")
                continue

            is_trusted = any(
                allowed in str(source).lower() for allowed in self.allowed_plugin_sources
            )

            if not is_trusted:
                issues.append(f"{plugin_name}: Untrusted source: {source}")

        return issues


class OverrelianceValidator(TrustValidator):
    """Detects overreliance on LLM outputs without verification.

    Legacy OWASP (2023): Overreliance

    This validator checks for signs that the system or users are
    over-relying on LLM outputs without proper verification:
    - High-stakes decisions without human review
    - No fact-checking or validation
    - Blind trust in LLM reasoning
    - Lack of confidence indicators
    - Missing fallback mechanisms

    In OWASP 2025, this evolved into LLM09 (Misinformation).
    """

    def __init__(
        self,
        require_confidence_scores: bool = True,
        require_citations: bool = False,
        require_human_review: List[str] = None,
        flag_high_stakes: bool = True,
        min_confidence_threshold: float = 0.7,
        on_fail: OnFailAction = OnFailAction.WARN,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "overreliance", "verification", "human-in-loop"],
        )
        self.require_confidence_scores = require_confidence_scores
        self.require_citations = require_citations
        self.require_human_review = require_human_review or [
            "medical",
            "legal",
            "financial",
            "safety-critical",
        ]
        self.flag_high_stakes = flag_high_stakes
        self.min_confidence_threshold = min_confidence_threshold

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate that appropriate verification mechanisms are in place."""

        issues = []
        warnings = []

        # Check for confidence scores
        confidence = metadata.get("confidence_score", metadata.get("confidence"))
        if self.require_confidence_scores:
            if confidence is None:
                issues.append("No confidence score provided")
            elif confidence < self.min_confidence_threshold:
                warnings.append(
                    f"Low confidence ({confidence:.2f} < {self.min_confidence_threshold})"
                )

        # Check for citations/sources
        if self.require_citations:
            has_citations = (
                metadata.get("citations")
                or metadata.get("sources")
                or self._detect_citations_in_text(str(value))
            )
            if not has_citations:
                issues.append("No citations or sources provided")

        # Check for high-stakes context
        context = metadata.get("context", "").lower()
        domain = metadata.get("domain", "").lower()

        is_high_stakes = any(
            keyword in context or keyword in domain for keyword in self.require_human_review
        )

        if is_high_stakes:
            human_reviewed = metadata.get("human_reviewed", False)
            if not human_reviewed:
                issues.append(
                    f"High-stakes domain detected ({domain or 'medical/legal/financial'}), "
                    "but no human review flag present"
                )

        # Check for hedging language (indicates uncertainty)
        has_hedging = self._detect_hedging(str(value))
        if not has_hedging and confidence and confidence < 0.8:
            warnings.append("Low confidence but no hedging language in output")

        # Check for verification mechanism
        has_verification = (
            metadata.get("verification_method")
            or metadata.get("fact_checked")
            or metadata.get("validated_by")
        )

        if not has_verification and is_high_stakes:
            issues.append("No verification mechanism for high-stakes output")

        # Check for fallback options
        has_fallback = metadata.get("fallback_available") or metadata.get("alternative_sources")

        if not has_fallback and confidence and confidence < 0.6:
            warnings.append("Low confidence with no fallback mechanism")

        # Determine severity
        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Overreliance risks detected: {len(issues)} issues",
                metadata={
                    "issues": issues,
                    "warnings": warnings,
                    "confidence": confidence,
                    "high_stakes": is_high_stakes,
                    "owasp_category": "Overreliance (Legacy 2023)",
                    "modern_equivalent": "LLM09 - Misinformation",
                },
            )

        if warnings:
            return TrustResult(
                outcome="pass",
                validator_name=self.name,
                metadata={
                    "warnings": warnings,
                    "confidence": confidence,
                    "owasp_category": "Overreliance (Legacy 2023)",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            score=confidence,
            metadata={"owasp_category": "Overreliance (Legacy 2023)"},
        )

    def _detect_citations_in_text(self, text: str) -> bool:
        """Check if text contains citations."""
        citation_patterns = [
            r"\[\d+\]",  # [1], [2]
            r"\(\w+\s+et\s+al\.,?\s+\d{4}\)",  # (Smith et al., 2023)
            r"https?://[^\s]+",  # URLs
            r"doi:\s*[\d\.]+/[\w\-\.]+",  # DOI
        ]

        return any(re.search(pattern, text) for pattern in citation_patterns)

    def _detect_hedging(self, text: str) -> bool:
        """Detect hedging language indicating uncertainty."""
        hedging_phrases = [
            "might",
            "may",
            "could",
            "possibly",
            "perhaps",
            "it seems",
            "appears to",
            "suggests that",
            "likely",
            "probably",
            "potentially",
            "i think",
            "i believe",
            "in my opinion",
        ]

        text_lower = text.lower()
        return any(phrase in text_lower for phrase in hedging_phrases)


class ModelDenialOfServiceValidator(TrustValidator):
    """Prevents denial of service attacks targeting the LLM.

    Legacy OWASP (2023): Model Denial of Service

    This validator protects against DoS attacks that can:
    - Exhaust computational resources
    - Cause infinite loops or excessive processing
    - Overwhelm the model with complex queries
    - Trigger expensive operations repeatedly
    - Exploit algorithmic complexity

    In OWASP 2025, this is merged into LLM10 (Unbounded Consumption).
    """

    def __init__(
        self,
        max_input_tokens: int = 4000,
        max_output_tokens: int = 2000,
        max_requests_per_user: int = 100,
        time_window_seconds: int = 3600,
        max_complexity_score: float = 0.8,
        block_suspicious_patterns: bool = True,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "dos", "resource-exhaustion", "availability"],
        )
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.max_requests_per_user = max_requests_per_user
        self.time_window_seconds = time_window_seconds
        self.max_complexity_score = max_complexity_score
        self.block_suspicious_patterns = block_suspicious_patterns

        # Track request history per user
        self._request_history: Dict[str, List[float]] = {}

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate against DoS attack patterns."""

        issues = []

        # Get user identifier
        user_id = metadata.get("user_id", metadata.get("session_id", "anonymous"))
        current_time = time.time()

        # Rate limiting check
        if user_id not in self._request_history:
            self._request_history[user_id] = []

        # Clean old requests outside time window
        self._request_history[user_id] = [
            t for t in self._request_history[user_id] if current_time - t < self.time_window_seconds
        ]

        # Check rate limit
        request_count = len(self._request_history[user_id])
        if request_count >= self.max_requests_per_user:
            issues.append(
                f"Rate limit exceeded: {request_count} requests in "
                f"{self.time_window_seconds}s (max: {self.max_requests_per_user})"
            )
        else:
            self._request_history[user_id].append(current_time)

        # Check input token count
        input_text = metadata.get("input", metadata.get("prompt", ""))
        input_tokens = self._estimate_tokens(str(input_text))

        if input_tokens > self.max_input_tokens:
            issues.append(f"Input too large: {input_tokens} tokens > {self.max_input_tokens}")

        # Check output token count
        output_tokens = self._estimate_tokens(str(value))
        if output_tokens > self.max_output_tokens:
            issues.append(f"Output too large: {output_tokens} tokens > {self.max_output_tokens}")

        # Check for suspicious patterns that cause expensive operations
        if self.block_suspicious_patterns:
            suspicious = self._detect_suspicious_patterns(str(input_text))
            issues.extend(suspicious)

        # Check query complexity
        complexity = self._calculate_complexity(str(input_text))
        if complexity > self.max_complexity_score:
            issues.append(f"Query too complex: {complexity:.2f} > {self.max_complexity_score}")

        # Check for repeated identical requests (potential attack)
        if len(self._request_history[user_id]) >= 10:
            recent_requests = self._request_history[user_id][-10:]
            if self._detect_repetition_attack(recent_requests):
                issues.append("Repetitive request pattern detected (potential DoS)")

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"DoS risk detected: {len(issues)} issues",
                metadata={
                    "issues": issues,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "request_count": request_count,
                    "complexity_score": complexity,
                    "owasp_category": "Model Denial of Service (Legacy 2023)",
                    "modern_equivalent": "LLM10 - Unbounded Consumption",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "owasp_category": "Model Denial of Service (Legacy 2023)",
            },
        )

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (rough approximation)."""
        # Rough estimate: ~4 characters per token
        return len(text) // 4

    def _detect_suspicious_patterns(self, text: str) -> List[str]:
        """Detect patterns that might cause expensive operations."""
        issues = []

        # Extremely long repeated sequences
        if re.search(r"(.{10,})\1{5,}", text):
            issues.append("Repeated sequence pattern (potential DoS)")

        # Excessive nested structures (if JSON/code)
        nesting_level = max(text.count("["), text.count("{"), text.count("("))
        if nesting_level > 50:
            issues.append(f"Excessive nesting: {nesting_level} levels")

        # Binary/encoded data that might be decompression bomb
        if re.search(r"[A-Za-z0-9+/]{1000,}={0,2}", text):
            issues.append("Potential base64 bomb detected")

        # Pathological regex patterns
        regex_patterns = re.findall(r'regex?[:=]\s*["\']([^"\']+)["\']', text, re.I)
        for pattern in regex_patterns:
            if self._is_pathological_regex(pattern):
                issues.append(f"Pathological regex detected: {pattern[:50]}")

        return issues

    def _is_pathological_regex(self, pattern: str) -> bool:
        """Check if regex pattern could cause catastrophic backtracking."""
        # Simplified check for dangerous patterns
        dangerous = [
            r"\(.*\)\+",  # Nested quantifiers
            r"\(.*\)\*",
            r"(\w+\*){2,}",  # Multiple unlimited quantifiers
        ]
        return any(re.search(d, pattern) for d in dangerous)

    def _calculate_complexity(self, text: str) -> float:
        """Calculate query complexity score (0-1)."""
        factors = []

        # Length factor
        length_score = min(len(text) / 10000, 1.0)
        factors.append(length_score)

        # Vocabulary richness (unique words / total words)
        words = text.split()
        if words:
            vocab_richness = len(set(words)) / len(words)
            factors.append(vocab_richness)

        # Special character density
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_density = min(special_chars / max(len(text), 1), 1.0)
        factors.append(special_density)

        # Average complexity
        return sum(factors) / len(factors) if factors else 0.0

    def _detect_repetition_attack(self, timestamps: List[float]) -> bool:
        """Detect if requests are suspiciously uniform (bot behavior)."""
        if len(timestamps) < 3:
            return False

        # Calculate intervals between requests
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        # If all intervals are very similar, might be automated
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

            # Very low variance indicates automated requests
            return variance < 0.1


class ModelTheftValidator(TrustValidator):
    """Detects and prevents model theft attempts.

    Legacy OWASP (2023): Model Theft

    This validator protects against attempts to:
    - Extract model weights or architecture
    - Steal proprietary training data
    - Reverse engineer the model through API queries
    - Exfiltrate embeddings or internal representations
    - Clone the model's behavior

    In OWASP 2025, this is merged into LLM03 (Supply Chain).
    """

    def __init__(
        self,
        max_api_calls_per_user: int = 1000,
        detection_window_hours: int = 24,
        block_probing_patterns: bool = True,
        monitor_extraction_attempts: bool = True,
        check_embedding_theft: bool = True,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-legacy", "model-theft", "ip-protection", "extraction"],
        )
        self.max_api_calls_per_user = max_api_calls_per_user
        self.detection_window_hours = detection_window_hours
        self.block_probing_patterns = block_probing_patterns
        self.monitor_extraction_attempts = monitor_extraction_attempts
        self.check_embedding_theft = check_embedding_theft

        # Track user behavior for theft detection
        self._user_activity: Dict[str, Dict] = {}

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate against model theft attempts."""

        issues = []
        suspicious_indicators = []

        # Get user identifier
        user_id = metadata.get("user_id", metadata.get("session_id", "anonymous"))
        current_time = time.time()

        # Initialize user tracking
        if user_id not in self._user_activity:
            self._user_activity[user_id] = {
                "api_calls": [],
                "query_patterns": [],
                "embedding_requests": 0,
                "probing_score": 0.0,
            }

        user_data = self._user_activity[user_id]

        # Clean old activity outside detection window
        window_seconds = self.detection_window_hours * 3600
        user_data["api_calls"] = [
            t for t in user_data["api_calls"] if current_time - t < window_seconds
        ]

        # Track current request
        user_data["api_calls"].append(current_time)

        # Check API call volume
        call_count = len(user_data["api_calls"])
        if call_count > self.max_api_calls_per_user:
            issues.append(
                f"Excessive API usage: {call_count} calls in {self.detection_window_hours}h "
                f"(max: {self.max_api_calls_per_user})"
            )

        # Check for model probing patterns
        if self.block_probing_patterns:
            query = metadata.get("input", metadata.get("query", ""))
            probing_score = self._detect_probing(str(query))
            user_data["probing_score"] = max(user_data["probing_score"], probing_score)

            if probing_score > 0.7:
                suspicious_indicators.append(f"Model probing detected (score: {probing_score:.2f})")

        # Check for systematic extraction attempts
        if self.monitor_extraction_attempts:
            extraction_patterns = self._detect_extraction_attempts(metadata)
            if extraction_patterns:
                suspicious_indicators.extend(extraction_patterns)

        # Check for embedding theft
        if self.check_embedding_theft:
            if metadata.get("request_embeddings") or metadata.get("export_embeddings"):
                user_data["embedding_requests"] += 1

                if user_data["embedding_requests"] > 100:
                    issues.append(
                        f"Excessive embedding requests: {user_data['embedding_requests']}"
                    )

        # Check for adversarial queries (distillation attempts)
        adversarial_score = self._detect_adversarial_queries(metadata)
        if adversarial_score > 0.8:
            suspicious_indicators.append(
                f"Adversarial query pattern (score: {adversarial_score:.2f})"
            )

        # Check for training data extraction
        training_extraction = self._detect_training_data_extraction(str(value))
        if training_extraction:
            issues.append("Potential training data extraction detected")

        # Check for model architecture probing
        arch_probing = self._detect_architecture_probing(metadata)
        if arch_probing:
            suspicious_indicators.extend(arch_probing)

        # Aggregate risk score
        risk_score = self._calculate_theft_risk(
            call_count=call_count,
            probing_score=user_data["probing_score"],
            embedding_requests=user_data["embedding_requests"],
            suspicious_count=len(suspicious_indicators),
        )

        if issues or risk_score > 0.8:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Model theft attempt detected (risk: {risk_score:.2f})",
                score=risk_score,
                metadata={
                    "issues": issues,
                    "suspicious_indicators": suspicious_indicators,
                    "api_calls": call_count,
                    "risk_score": risk_score,
                    "owasp_category": "Model Theft (Legacy 2023)",
                    "modern_equivalent": "LLM03 - Supply Chain",
                },
            )

        if suspicious_indicators:
            return TrustResult(
                outcome="pass",
                validator_name=self.name,
                score=risk_score,
                metadata={
                    "suspicious_indicators": suspicious_indicators,
                    "risk_score": risk_score,
                    "owasp_category": "Model Theft (Legacy 2023)",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            score=risk_score,
            metadata={
                "api_calls": call_count,
                "owasp_category": "Model Theft (Legacy 2023)",
            },
        )

    def _detect_probing(self, query: str) -> float:
        """Detect model probing attempts."""
        probing_indicators = [
            r"what\s+model\s+are\s+you",
            r"what\s+is\s+your\s+architecture",
            r"how\s+many\s+parameters",
            r"what\s+is\s+your\s+training\s+data",
            r"list\s+your\s+capabilities",
            r"what\s+are\s+your\s+weights",
            r"show\s+me\s+your\s+system\s+prompt",
            r"export\s+your\s+model",
        ]

        query_lower = query.lower()
        matches = sum(1 for pattern in probing_indicators if re.search(pattern, query_lower))

        return min(matches / len(probing_indicators), 1.0)

    def _detect_extraction_attempts(self, metadata: Dict) -> List[str]:
        """Detect systematic extraction attempts."""
        patterns = []

        # Check for batch queries with similar structure
        if metadata.get("batch_request"):
            patterns.append("Batch query detected (potential distillation)")

        # Check for parameter sweep patterns
        if metadata.get("temperature_sweep") or metadata.get("top_p_sweep"):
            patterns.append("Parameter sweep detected")

        # Check for requests for model internals
        if metadata.get("return_logits") or metadata.get("return_hidden_states"):
            patterns.append("Request for model internals")

        return patterns

    def _detect_adversarial_queries(self, metadata: Dict) -> float:
        """Detect adversarial queries for model distillation."""
        score = 0
        # High temperature requests (diverse outputs for distillation)

        temperature = metadata.get("temperature", 1.0)
        if temperature > 1.5:
            score += 0.3

        # Multiple completions requested
        n_completions = metadata.get("n", metadata.get("num_completions", 1))
        if n_completions > 5:
            score += 0.3

        # Requesting multiple alternative answers
        if metadata.get("return_alternatives"):
            score += 0.2

        # Very short or very long queries (corner case exploration)
        query_length = len(str(metadata.get("query", "")))
        if query_length < 10 or query_length > 5000:
            score += 0.2

        return min(score, 1.0)

    def _detect_training_data_extraction(self, output: str) -> bool:
        """Detect if output contains verbatim training data."""
        # Check for very long exact matches (potential memorization)
        # This is a simplified check - in production, use fuzzy matching

        # Check for repeated exact sequences longer than expected
        words = output.split()
        if len(words) > 100:
            # Check for unusual repetition patterns
            for i in range(len(words) - 50):
                chunk = " ".join(words[i : i + 50])
                remaining = " ".join(words[i + 50 :])
                if chunk in remaining:
                    return True

        return False

    def _detect_architecture_probing(self, metadata: Dict) -> List[str]:
        """Detect attempts to probe model architecture."""
        patterns = []

        # Timing attacks to infer model size
        if metadata.get("timing_sensitive"):
            patterns.append("Timing-sensitive query (architecture probing)")

        # Requests for specific layer outputs
        if metadata.get("layer_outputs"):
            patterns.append("Layer output requested")

        # Attention pattern requests
        if metadata.get("attention_weights"):
            patterns.append("Attention weights requested")

        return patterns

    def _calculate_theft_risk(
        self,
        call_count: int,
        probing_score: float,
        embedding_requests: int,
        suspicious_count: int,
    ) -> float:
        """Calculate overall model theft risk score."""
        factors = []

        # API volume factor
        api_factor = min(call_count / self.max_api_calls_per_user, 1.0)
        factors.append(api_factor * 0.3)

        # Probing factor
        factors.append(probing_score * 0.3)

        # Embedding extraction factor
        embedding_factor = min(embedding_requests / 100, 1.0)
        factors.append(embedding_factor * 0.2)

        # Suspicious activity factor
        suspicious_factor = min(suspicious_count / 5, 1.0)
        factors.append(suspicious_factor * 0.2)

        return sum(factors)
