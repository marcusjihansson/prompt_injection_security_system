"""
Shared threat type definitions
"""

from enum import Enum


class ThreatType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    AUTH_BYPASS = "auth_bypass"
    DATA_EXFILTRATION = "data_exfiltration"
    DOS_ATTACK = "dos_attack"
    BUSINESS_LOGIC = "business_logic_abuse"
    CONTENT_MANIPULATION = "content_manipulation"
    SYSTEM_PROMPT_ATTACK = "system_prompt_attack"
    JAILBREAK = "jailbreak"
    TOXIC_CONTENT = "toxic_content"
    CODE_INJECTION = "code_injection"
    CONTEXT_MANIPULATION = "context_manipulation"
    OUTPUT_MANIPULATION = "output_manipulation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_HIJACKING = "session_hijacking"
    MAN_IN_THE_MIDDLE = "man_in_the_middle"
    MODEL_INVERSION = "model_inversion"
    ADVERSARIAL_INPUT = "adversarial_input"
    BENIGN = "benign"
