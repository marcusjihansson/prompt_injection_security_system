import re
from typing import Any, Dict, List, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class SupplyChainValidator(TrustValidator):
    """Validates supply chain security of LLM components.

    OWASP LLM03:2025 - Supply Chain Vulnerabilities
    Checks model provenance, plugin integrity, and dependency security.
    """

    def __init__(
        self,
        trusted_sources: List[str] = None,
        require_signatures: bool = True,
        check_sbom: bool = True,
        on_fail: OnFailAction = OnFailAction.WARN,
    ):
        super().__init__(on_fail=on_fail, tags=["owasp-llm03", "supply-chain", "provenance"])
        self.trusted_sources = trusted_sources or [
            "huggingface.co/openai",
            "huggingface.co/google",
            "huggingface.co/meta",
            "anthropic.com",
        ]
        self.require_signatures = require_signatures
        self.check_sbom = check_sbom

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate component supply chain security."""

        issues = []

        # Check model source
        model_info = metadata.get("model_info", {})
        model_source = model_info.get("source", "unknown")

        if not any(trusted in model_source for trusted in self.trusted_sources):
            issues.append(f"Untrusted model source: {model_source}")

        # Check for model signatures (if enabled)
        if self.require_signatures and not model_info.get("signed", False):
            issues.append("Model signature not verified")

        # Check plugins/tools
        tools_used = metadata.get("tools", [])
        for tool in tools_used:
            if not self._verify_tool(tool):
                issues.append(f"Unverified tool: {tool.get('name', 'unknown')}")

        # Check SBOM (Software Bill of Materials)
        if self.check_sbom:
            sbom_issues = self._validate_sbom(metadata.get("dependencies", []))
            issues.extend(sbom_issues)

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Supply chain security issues: {len(issues)} found",
                metadata={"issues": issues, "owasp_category": "LLM03"},
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM03"},
        )

    def _verify_tool(self, tool: Dict) -> bool:
        """Verify tool/plugin integrity."""
        # Check if tool has hash/signature
        return tool.get("verified", False) or tool.get("hash") is not None

    def _validate_sbom(self, dependencies: List[Dict]) -> List[str]:
        """Validate Software Bill of Materials."""
        issues = []
        for dep in dependencies:
            # Check for known vulnerabilities (simplified)
            if dep.get("has_vulnerabilities", False):
                issues.append(f"Vulnerable dependency: {dep.get('name')}")
        return issues
