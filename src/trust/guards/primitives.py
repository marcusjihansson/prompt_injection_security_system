"""
chain_of_trust/primitives.py
Defines the core trust levels and secure field types.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class TrustLevel(Enum):
    """Trust levels for data flowing through DSPy pipelines"""

    SYSTEM = 0  # Highest trust - framework/developer instructions
    VERIFIED = 1  # Authenticated/validated external data (e.g. RAG context)
    USER = 2  # Untrusted user input
    DERIVED = 3  # Output from LLM calls (inherits source trust)

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


@dataclass
class SecureField:
    """Field definition with attached trust level"""

    description: str
    trust_level: TrustLevel = TrustLevel.USER
    required: bool = True
    sanitize: bool = True  # Auto-sanitize if USER level

    def validate(self, value: Any) -> bool:
        if self.required and value is None:
            return False
        return True
