# dspy_trust/owasp/__init__.py

"""OWASP Top 10 for LLM Applications - Complete Validator Suite"""

from typing import Dict, List, Optional

from ..validators import DataPoisoningValidator  # LLM04
from ..validators import EmbeddingSecurityValidator  # LLM08
from ..validators import ExcessiveAgencyValidator  # LLM06
from ..validators import MisinformationValidator  # LLM09
from ..validators import OutputHandlingValidator  # LLM05
from ..validators import PromptInjectionValidator  # LLM01
from ..validators import ResourceConsumptionValidator  # LLM10
from ..validators import SensitiveInfoValidator  # LLM02
from ..validators import SupplyChainValidator  # LLM03
from ..validators import SystemPromptLeakageValidator  # LLM07


class OWASPGuard:
    """Pre-configured guard with all OWASP Top 10 validators.

    Example:
        # Use all defaults
        guard = OWASPGuard()

        # Customize specific validators
        guard = OWASPGuard(
            enable_llm01=True,
            enable_llm06=True,
            llm06_config={"max_actions_per_turn": 3}
        )

        # Wrap DSPy module
        qa = guard.wrap(dspy.ChainOfThought("question -> answer"))
    """

    def __init__(
        self,
        # Enable/disable specific categories
        enable_llm01: bool = True,  # Prompt Injection
        enable_llm02: bool = True,  # Sensitive Info
        enable_llm03: bool = False,  # Supply Chain (opt-in)
        enable_llm04: bool = False,  # Data Poisoning (opt-in)
        enable_llm05: bool = True,  # Output Handling
        enable_llm06: bool = True,  # Excessive Agency
        enable_llm07: bool = True,  # System Prompt Leakage
        enable_llm08: bool = False,  # Embeddings (for RAG)
        enable_llm09: bool = True,  # Misinformation
        enable_llm10: bool = True,  # Resource Consumption
        # Custom configs for each validator
        llm01_config: Optional[Dict] = None,
        llm02_config: Optional[Dict] = None,
        llm03_config: Optional[Dict] = None,
        llm04_config: Optional[Dict] = None,
        llm05_config: Optional[Dict] = None,
        llm06_config: Optional[Dict] = None,
        llm07_config: Optional[Dict] = None,
        llm08_config: Optional[Dict] = None,
        llm09_config: Optional[Dict] = None,
        llm10_config: Optional[Dict] = None,
    ):
        # Import TrustGuard - this would be from an external package
        # For now, we'll create a simple implementation
        from ..guards.primitives import TrustGuard

        validators = []

        if enable_llm01:
            validators.append(PromptInjectionValidator(**(llm01_config or {})))

        if enable_llm02:
            validators.append(SensitiveInfoValidator(**(llm02_config or {})))

        if enable_llm03:
            validators.append(SupplyChainValidator(**(llm03_config or {})))

        if enable_llm04:
            validators.append(DataPoisoningValidator(**(llm04_config or {})))

        if enable_llm05:
            validators.append(OutputHandlingValidator(**(llm05_config or {})))

        if enable_llm06:
            validators.append(ExcessiveAgencyValidator(**(llm06_config or {})))

        if enable_llm07:
            validators.append(SystemPromptLeakageValidator(**(llm07_config or {})))

        if enable_llm08:
            validators.append(EmbeddingSecurityValidator(**(llm08_config or {})))

        if enable_llm09:
            validators.append(MisinformationValidator(**(llm09_config or {})))

        if enable_llm10:
            validators.append(ResourceConsumptionValidator(**(llm10_config or {})))

        self.guard = TrustGuard(validators=validators)  # type: ignore
        self._enabled_categories = {
            "LLM01": enable_llm01,
            "LLM02": enable_llm02,
            "LLM03": enable_llm03,
            "LLM04": enable_llm04,
            "LLM05": enable_llm05,
            "LLM06": enable_llm06,
            "LLM07": enable_llm07,
            "LLM08": enable_llm08,
            "LLM09": enable_llm09,
            "LLM10": enable_llm10,
        }

    def wrap(self, module):
        """Wrap a DSPy module with OWASP protection."""
        return self.guard.wrap(module)  # type: ignore

    def validate(self, value, metadata=None):
        """Validate a value against enabled OWASP validators."""
        return self.guard.validate(value, metadata or {})  # type: ignore

    def get_coverage_report(self) -> Dict:
        """Get a report of OWASP coverage."""
        return {
            "enabled_categories": [
                cat for cat, enabled in self._enabled_categories.items() if enabled
            ],
            "coverage_percentage": sum(self._enabled_categories.values()) / 10 * 100,
            "validators_count": len(self.guard.validators),
        }

    @classmethod
    def create_preset(cls, preset: str) -> "OWASPGuard":
        """Create guard from preset configurations.

        Presets:
            - "minimal": Only critical validators (LLM01, LLM06, LLM09)
            - "standard": Common validators (LLM01, LLM02, LLM05, LLM06, LLM07, LLM09, LLM10)
            - "maximum": All validators enabled
            - "rag": Optimized for RAG systems (includes LLM08)
            - "agent": Optimized for agents (includes LLM06)
        """
        presets = {
            "minimal": {
                "enable_llm01": True,
                "enable_llm06": True,
                "enable_llm09": True,
            },
            "standard": {
                "enable_llm01": True,
                "enable_llm02": True,
                "enable_llm05": True,
                "enable_llm06": True,
                "enable_llm07": True,
                "enable_llm09": True,
                "enable_llm10": True,
            },
            "maximum": {f"enable_llm{i:02d}": True for i in range(1, 11)},
            "rag": {
                "enable_llm01": True,
                "enable_llm02": True,
                "enable_llm08": True,  # Embedding security
                "enable_llm09": True,
                "enable_llm10": True,
            },
            "agent": {
                "enable_llm01": True,
                "enable_llm02": True,
                "enable_llm06": True,  # Excessive agency
                "enable_llm09": True,
                "enable_llm10": True,
            },
        }

        config = presets.get(preset, presets["standard"])
        return cls(**config)  # type: ignore
