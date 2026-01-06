"""
Insecure Plugin Design Validator

Legacy OWASP LLM Top 10 (2023): Insecure Plugin Design
Modern Equivalent: Absorbed into LLM03 - Supply Chain (2025)

This validator checks for common plugin/tool security issues:
- Insufficient input validation
- Lack of authorization checks
- Unsafe parameter handling
- Missing rate limiting
- Inadequate error handling
- Overly permissive capabilities

Use in strict scenarios where plugin security is critical.
"""

import re
from typing import Any, Dict, List, Literal, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class InsecurePluginValidator(TrustValidator):
    """Validates plugin/tool security and design.

    This validator checks for common plugin security issues including:
    insufficient input validation, lack of authorization checks,
    unsafe parameter handling, and overly permissive capabilities.

    Note: This is a legacy validator from OWASP 2023. In OWASP 2025,
    this category is merged into LLM03 (Supply Chain).
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
