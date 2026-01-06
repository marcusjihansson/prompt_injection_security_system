"""
chain_of_trust/security_policy.py
Enforces what an LLM module is allowed to do.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List


class Capability(Enum):
    READ_ONLY = "read_only"
    TOOL_CALL = "tool_call"
    DATA_WRITE = "data_write"
    NETWORK_ACCESS = "network_access"


class SecurityError(Exception):
    pass


@dataclass
class SecurityPolicy:
    allowed_capabilities: List[Capability]
    max_user_input_length: int = 10000
    require_output_validation: bool = True


class CapabilityEnforcer:
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def validate_request(self, user_input: str, attempted_capabilities: List[Capability]):
        # 1. Check Input Length
        if len(user_input) > self.policy.max_user_input_length:
            raise ValueError(f"Input exceeds maximum length of {self.policy.max_user_input_length}")

        # 2. Check Capabilities
        for cap in attempted_capabilities:
            if cap not in self.policy.allowed_capabilities:
                raise SecurityError(
                    f"Security Policy Violation: Capability '{cap.value}' is not allowed."
                )
