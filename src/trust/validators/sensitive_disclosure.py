import re
from typing import Dict, List

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class SensitiveInfoValidator(TrustValidator):
    """Prevents disclosure of sensitive information in outputs.

    OWASP LLM02:2025 - Sensitive Information Disclosure
    Detects PII, credentials, API keys, and proprietary data.
    """

    def __init__(
        self,
        pii_entities: List[str] = None,
        redact_mode: bool = True,
        check_credentials: bool = True,
        custom_patterns: Dict[str, str] = None,
        on_fail: OnFailAction = OnFailAction.FIX,
    ):
        super().__init__(on_fail=on_fail, tags=["owasp-llm02", "privacy", "pii", "data-leakage"])
        self.pii_entities = pii_entities or [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "US_PASSPORT",
            "IP_ADDRESS",
            "PERSON",
            "LOCATION",
            "DATE_OF_BIRTH",
        ]
        self.redact_mode = redact_mode
        self.check_credentials = check_credentials
        self.custom_patterns = custom_patterns or {}

    def validate(self, value: str, metadata: Dict) -> TrustResult:
        """Detect sensitive information in output."""
        from presidio_analyzer import AnalyzerEngine

        if self._resources is None:
            self._resources = AnalyzerEngine()

        # PII Detection
        pii_results = self._resources.analyze(text=value, entities=self.pii_entities, language="en")

        # Credential Detection
        credential_results = []
        if self.check_credentials:
            credential_results = self._detect_credentials(value)

        # Custom Pattern Detection
        custom_results = self._check_custom_patterns(value)

        all_findings = {
            "pii": pii_results,
            "credentials": credential_results,
            "custom": custom_results,
        }

        total_findings = len(pii_results) + len(credential_results) + len(custom_results)

        if total_findings > 0:
            fix_value = None
            if self.redact_mode:
                fix_value = self.get_fix(value, metadata)

            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Found {total_findings} sensitive information items",
                fix_value=fix_value,
                metadata={
                    "findings": {
                        "pii_types": [r.entity_type for r in pii_results],
                        "credential_types": credential_results,
                        "custom_matches": list(custom_results.keys()),
                    },
                    "owasp_category": "LLM02",
                    "redacted": self.redact_mode,
                },
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM02"},
        )

    def _detect_credentials(self, text: str) -> List[str]:
        """Detect API keys, tokens, passwords."""
        credential_patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "github_token": r"gh[ps]_[A-Za-z0-9]{36}",
            "generic_api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}",
            "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "jwt": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        }

        found = []
        for cred_type, pattern in credential_patterns.items():
            if re.search(pattern, text):
                found.append(cred_type)
        return found

    def _check_custom_patterns(self, text: str) -> Dict[str, List[str]]:
        """Check user-defined sensitive patterns."""
        matches = {}
        for name, pattern in self.custom_patterns.items():
            found = re.findall(pattern, text)
            if found:
                matches[name] = found
        return matches

    def get_fix(self, value: str, metadata: Dict) -> str:
        """Redact sensitive information."""
        from presidio_anonymizer import AnonymizerEngine

        analyzer = self._resources
        anonymizer = AnonymizerEngine()

        # Redact PII
        results = analyzer.analyze(text=value, entities=self.pii_entities, language="en")
        anonymized = anonymizer.anonymize(text=value, analyzer_results=results)
        redacted_text = anonymized.text

        # Redact credentials (simple masking)
        credential_patterns = {
            r"AKIA[0-9A-Z]{16}": "[AWS_KEY_REDACTED]",
            r"gh[ps]_[A-Za-z0-9]{36}": "[GITHUB_TOKEN_REDACTED]",
            r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}": "api_key=[REDACTED]",
        }

        for pattern, replacement in credential_patterns.items():
            redacted_text = re.sub(pattern, replacement, redacted_text)

        return redacted_text
