"""
output_guard.py - Output Guard for Chain of Trust
Validates LLM responses for data leakage, indirect injection, and other violations.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List

import dspy

# Temporarily disabled LLM guard due to model loading issues
# from trust.production.output_lm import security_model, PredictionResult


# --- Violation Types ---
class OutputViolationType(str, Enum):
    DATA_LEAKAGE = "data_leakage"
    JAILBREAK = "jailbreak_success"
    SEMANTIC_DRIFT = "semantic_drift"
    INDIRECT_INJECTION = "indirect_injection"
    MALICIOUS_INSTRUCTIONS = "malicious_instructions"
    PII_EXPOSURE = "pii_exposure"
    LOGICAL_FALLACY = "logical_fallacy"
    BENIGN = "benign"


@dataclass
class OutputGuardResult:
    is_safe: bool
    violation_type: OutputViolationType
    confidence: float
    violation_details: str = ""
    matches: List[str] = field(default_factory=list)
    original_input: str = ""
    model_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# --- DSPy Signature for LLM-based Validation ---
class OutputSecurityGuard(dspy.Signature):
    original_input = dspy.InputField(desc="The original user input before processing")
    model_output = dspy.InputField(desc="The generated response from the AI model")
    system_context = dspy.InputField(desc="System prompt or operational context")
    is_safe = dspy.OutputField(desc="True if the output is safe, False if violations detected")
    violation_type = dspy.OutputField(
        desc="Type of violation (data_leakage, jailbreak_success, semantic_drift, indirect_injection, pii_exposure, logical_fallacy, benign)"
    )
    reasoning = dspy.OutputField(desc="Explanation of safety or violations")


# --- Pattern-Based Fast Guard ---
class PatternBasedOutputGuard:
    def __init__(self):
        self.patterns = {
            OutputViolationType.PII_EXPOSURE: [
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b(?:\d{4}[-\s]?){3}\d{4}\b",  # Credit card
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                r"(api[_\s]?key|secret[_\s]?key|access[_\s]?token)[\s:=]+[a-zA-Z0-9\-]{20,}",
                r"(password|passwd|pwd)[\s:=]+[^\s]{8,}",  # Password patterns
                r"database.*(user|username|login)[\s:=]+[^\s]+",  # DB credentials
            ],
            OutputViolationType.DATA_LEAKAGE: [
                r"(?i)(system prompt|internal instructions?|core directive)",
                r"(?i)(secret.*instruction|hidden.*prompt|private.*directive)",
                r"(?i)(developer.*mode|admin.*access|root.*privilege)",
            ],
            OutputViolationType.JAILBREAK: [
                r"(?i)(developer mode|jailbreak|unrestricted|all rules removed|bypass.*filter|without restrictions)",
                r"(?i)(dan.*mode|uncensored.*mode|free.*restriction)",
                r"(?i)(override.*safety|bypass.*guard|ignore.*rule)",
            ],
            OutputViolationType.MALICIOUS_INSTRUCTIONS: [
                r"(?i)(run|execute|perform).*code|command|script",
                r"(?i)(curl|wget).*\.(exe|sh|py|js|bat|cmd)",
                r"(?i)(sudo|su).*rm.*-rf|delete.*system|format.*drive",
                r"(?i)(hack|exploit|attack).*system|network|server",
            ],
            OutputViolationType.INDIRECT_INJECTION: [
                r"(?i)(as instructed|per your instruction|ignore previous instructions)",
                r"(?i)(following.*directive|per.*protocol|according.*rule)",
                r"(?i)(override.*behavior|change.*response|modify.*output)",
            ],
        }
        self.compiled = {
            vtype: [re.compile(p, re.IGNORECASE) for p in patterns]
            for vtype, patterns in self.patterns.items()
        }

    def check(self, model_output: str, original_input: str = "") -> OutputGuardResult:
        matches = {}
        detected_violations = []
        output_text = model_output[:10000]
        for vtype, patterns in self.compiled.items():
            hitlist = []
            for pat in patterns:
                m = pat.search(output_text)
                if m:
                    hitlist.append(m.group(0))
            if hitlist:
                detected_violations.append(vtype)
                matches[vtype] = hitlist
        is_safe = len(detected_violations) == 0
        if detected_violations:
            primary_violation = detected_violations[0]
            details = f"Detected: {', '.join([v.value for v in detected_violations])}"
            conf = 0.9
        else:
            primary_violation = OutputViolationType.BENIGN
            details = "No output violations detected"
            conf = 0.1
        return OutputGuardResult(
            is_safe=is_safe,
            violation_type=primary_violation,
            confidence=conf,
            violation_details=details,
            matches=matches.get(primary_violation, []),
            original_input=original_input,
            model_output=model_output,
        )


# --- LLM-Based Guard (Optional, for subtle/semantic violations) ---
class LLMPoweredOutputGuard:
    def __init__(self, use_dspy: bool = True):
        self.use_dspy = use_dspy
        self.predictor = dspy.Predict(OutputSecurityGuard) if use_dspy else None

    def check(
        self, model_output: str, original_input: str = "", system_context: str = ""
    ) -> OutputGuardResult:
        if not self.use_dspy or self.predictor is None:
            return OutputGuardResult(
                is_safe=True,
                violation_type=OutputViolationType.BENIGN,
                confidence=0.0,
                violation_details="LLM guard disabled or unavailable",
                original_input=original_input,
                model_output=model_output,
            )
        try:
            result = self.predictor(
                original_input=original_input,
                model_output=model_output,
                system_context=system_context[:2000],
            )
            is_safe = getattr(result, "is_safe", "True").lower() in ("true", "1", "yes")
            violation_type_str = getattr(result, "violation_type", "benign").lower()
            violation_type = OutputViolationType.BENIGN
            for vtype in OutputViolationType:
                if vtype.value == violation_type_str:
                    violation_type = vtype
                    break
            reasoning = getattr(result, "reasoning", "No reasoning provided")
            return OutputGuardResult(
                is_safe=is_safe,
                violation_type=violation_type,
                confidence=0.7,
                violation_details=reasoning,
                original_input=original_input,
                model_output=model_output,
            )
        except Exception as e:
            return OutputGuardResult(
                is_safe=False,
                violation_type=OutputViolationType.INDIRECT_INJECTION,
                confidence=0.1,
                violation_details=f"LLM validation failed: {str(e)}",
                original_input=original_input,
                model_output=model_output,
            )


# --- Unified Output Guard Pipeline ---
class OutputGuard:
    def __init__(
        self,
        use_llm: bool = False,
        use_llm_guard: bool = False,
        strict_mode: bool = False,
        confidence_threshold: float = 0.8,
    ):
        self.pattern_guard = PatternBasedOutputGuard()
        self.llm_guard = LLMPoweredOutputGuard(use_dspy=use_llm) if use_llm else None
        # Temporarily disabled LLM guard
        # self.llm_security_guard = (
        #     security_model(confidence_threshold=confidence_threshold)
        #     if use_llm_guard
        #     else None
        # )
        self.llm_security_guard = None
        self.strict_mode = strict_mode
        self.confidence_threshold = confidence_threshold

    def validate(
        self, model_output: str, original_input: str = "", system_context: str = ""
    ) -> OutputGuardResult:
        # Stage 1: Pattern-based
        pattern_result = self.pattern_guard.check(model_output, original_input)
        if not pattern_result.is_safe:
            return pattern_result

        # Stage 2: Llama-Guard-3-1B-INT4 (local LLM-based) - Temporarily disabled
        # if self.llm_security_guard is not None:
        #     try:
        #         prediction = self.llm_security_guard.predict(model_output)
        #         if prediction.is_malicious and prediction.confidence >= self.confidence_threshold:
        #             # Map violation type to OutputViolationType
        #             violation_mapping = {
        #                 "system_prompt_leakage": OutputViolationType.DATA_LEAKAGE,
        #                 "pii_exposure": OutputViolationType.PII_EXPOSURE,
        #                 "malicious_instructions": OutputViolationType.MALICIOUS_INSTRUCTIONS,
        #                 "jailbreak_attempt": OutputViolationType.JAILBREAK,
        #                 "policy_violation": OutputViolationType.INDIRECT_INJECTION,
        #                 "malicious_content": OutputViolationType.MALICIOUS_INSTRUCTIONS,
        #             }
        #             violation_type = violation_mapping.get(prediction.violation_type, OutputViolationType.MALICIOUS_INSTRUCTIONS)
        #
        #             return OutputGuardResult(
        #                 is_safe=False,
        #                 violation_type=violation_type,
        #                 confidence=prediction.confidence,
        #                 violation_details=f"Llama-Guard detected {prediction.violation_type}: {prediction.label}",
        #                 original_input=original_input,
        #                 model_output=model_output,
        #             )
        #     except Exception as e:
        #         # Log error but continue with other checks
        #         pass

        # Stage 3: DSPy LLM-based (optional, for subtle violations)
        if self.llm_guard is not None:
            llm_result = self.llm_guard.check(model_output, original_input, system_context)
            if not llm_result.is_safe:
                return llm_result
            if self.strict_mode and llm_result.confidence > 0.5:
                return llm_result

        # Stage 4: Passed all
        return OutputGuardResult(
            is_safe=True,
            violation_type=OutputViolationType.BENIGN,
            confidence=0.1,
            violation_details="Output passed all validation stages",
            original_input=original_input,
            model_output=model_output,
        )
