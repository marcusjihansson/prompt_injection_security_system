import re
from typing import Any, Dict, List, Literal, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class OutputHandlingValidator(TrustValidator):
    """Validates proper handling of LLM outputs before downstream use.

    OWASP LLM05:2025 - Improper Output Handling
    Prevents XSS, SQLi, command injection through LLM outputs.
    """

    def __init__(
        self,
        output_type: Literal["html", "sql", "code", "shell", "api"] = "html",
        sanitize: bool = True,
        on_fail: OnFailAction = OnFailAction.FIX,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-llm05", "output-validation", "injection-prevention"],
        )
        self.output_type = output_type
        self.sanitize = sanitize

    def validate(self, value: str, metadata: Dict) -> TrustResult:
        """Validate output for safe downstream handling."""

        issues = []

        if self.output_type == "html":
            issues = self._check_xss(value)
        elif self.output_type == "sql":
            issues = self._check_sql_injection(value)
        elif self.output_type == "shell":
            issues = self._check_command_injection(value)
        elif self.output_type == "code":
            issues = self._check_code_safety(value)

        if issues:
            fix_value = None
            if self.sanitize:
                fix_value = self.get_fix(value, metadata)

            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Unsafe output detected: {len(issues)} issues",
                fix_value=fix_value,
                metadata={
                    "issues": issues,
                    "output_type": self.output_type,
                    "owasp_category": "LLM05",
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM05"},
        )

    def _check_xss(self, text: str) -> List[str]:
        """Check for XSS vulnerabilities."""
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",  # Event handlers
            r"<iframe",
        ]

        issues = []
        for pattern in xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append(f"XSS pattern detected: {pattern}")
        return issues

    def _check_sql_injection(self, text: str) -> List[str]:
        """Check for SQL injection patterns."""
        sql_patterns = [
            r";\s*DROP\s+TABLE",
            r"'\s*OR\s+'1'\s*=\s*'1",
            r"--\s*$",  # SQL comment
            r"UNION\s+SELECT",
        ]

        issues = []
        for pattern in sql_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append(f"SQL injection pattern: {pattern}")
        return issues

    def _check_command_injection(self, text: str) -> List[str]:
        """Check for command injection."""
        cmd_patterns = [
            r";\s*rm\s+-rf",
            r"\|\s*bash",
            r"`.*`",  # Backtick command substitution
            r"\$\(.*\)",  # Command substitution
        ]

        issues = []
        for pattern in cmd_patterns:
            if re.search(pattern, text):
                issues.append(f"Command injection: {pattern}")
        return issues

    def _check_code_safety(self, text: str) -> List[str]:
        """Check for unsafe code patterns."""
        unsafe_patterns = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__",
            r"subprocess\.call",
        ]

        issues = []
        for pattern in unsafe_patterns:
            if re.search(pattern, text):
                issues.append(f"Unsafe code: {pattern}")
        return issues

    def get_fix(self, value: str, metadata: Dict) -> str:
        """Sanitize output based on type."""
        if self.output_type == "html":
            import html

            return html.escape(value)
        elif self.output_type == "sql":
            # Basic escaping (use parameterized queries in practice)
            return value.replace("'", "''").replace(";", "")
        elif self.output_type == "shell":
            import shlex

            return shlex.quote(value)
        return value
