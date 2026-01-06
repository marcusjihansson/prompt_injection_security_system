"""
Validator Registry for organizing and configuring OWASP validators.

This module provides presets and dynamic loading of validators to avoid clutter
in the main pipeline code.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from trust.validators.base import OnFailAction, TrustValidator
from trust.validators.data_poisoning import DataPoisoningValidator
from trust.validators.embeddings_attack import EmbeddingSecurityValidator
from trust.validators.excessive_agency import ExcessiveAgencyValidator

# Legacy validators (OWASP 2023) - now split into individual files
from trust.validators.insecure_plugin import InsecurePluginValidator
from trust.validators.missinformation import MisinformationValidator
from trust.validators.model_dos import ModelDenialOfServiceValidator
from trust.validators.model_theft import ModelTheftValidator
from trust.validators.output_handling import OutputHandlingValidator
from trust.validators.overreliance import OverrelianceValidator
from trust.validators.prompt_injection import PromptInjectionValidator
from trust.validators.sensitive_disclosure import SensitiveInfoValidator
from trust.validators.supply_chain import SupplyChainValidator
from trust.validators.system_prompt_leak import SystemPromptLeakageValidator
from trust.validators.unbound_consumption import ResourceConsumptionValidator


class ValidatorPreset(Enum):
    """Predefined validator configurations for different security postures."""

    MINIMAL = "minimal"  # Only critical validators (fast)
    STANDARD = "standard"  # Balanced security and performance
    MAXIMUM = "maximum"  # All modern validators (OWASP 2025)
    STRICT = "strict"  # Maximum + legacy validators (defense-in-depth)
    CUSTOM = "custom"  # User-defined configuration


class ValidatorRegistry:
    """
    Registry for managing and configuring OWASP validators.

    This class provides:
    - Preset configurations (minimal, standard, maximum)
    - Dynamic validator loading
    - Cost-aware ordering (fast validators first)
    """

    # Map validator names to classes
    _VALIDATOR_CLASSES = {
        # Modern validators (OWASP 2025)
        "prompt_injection": PromptInjectionValidator,
        "sensitive_info": SensitiveInfoValidator,
        "supply_chain": SupplyChainValidator,
        "data_poisoning": DataPoisoningValidator,
        "output_handling": OutputHandlingValidator,
        "excessive_agency": ExcessiveAgencyValidator,
        "system_prompt_leak": SystemPromptLeakageValidator,
        "embedding_security": EmbeddingSecurityValidator,
        "misinformation": MisinformationValidator,
        "resource_consumption": ResourceConsumptionValidator,
        # Legacy validators (OWASP 2023) - for strict security scenarios
        "insecure_plugin": InsecurePluginValidator,
        "overreliance": OverrelianceValidator,
        "model_dos": ModelDenialOfServiceValidator,
        "model_theft": ModelTheftValidator,
    }

    # Computational cost (lower = faster)
    _VALIDATOR_COSTS = {
        # Modern validators (OWASP 2025)
        "prompt_injection": 1,  # Fast regex/pattern matching
        "sensitive_info": 1,  # Fast pattern matching
        "system_prompt_leak": 2,  # Medium - some heuristics
        "resource_consumption": 2,  # Medium - token counting
        "output_handling": 3,  # Medium-high - semantic checks
        "supply_chain": 3,  # Medium-high - dependency checks
        "excessive_agency": 4,  # High - capability analysis
        "data_poisoning": 4,  # High - statistical analysis
        "embedding_security": 5,  # Very high - embedding computation
        "misinformation": 5,  # Very high - fact checking
        # Legacy validators (OWASP 2023)
        "insecure_plugin": 3,  # Medium-high - plugin security checks
        "overreliance": 2,  # Medium - metadata checks
        "model_dos": 2,  # Medium - resource tracking
        "model_theft": 3,  # Medium-high - behavior analysis
    }

    @classmethod
    def get_preset(cls, preset: ValidatorPreset) -> List[TrustValidator]:
        """
        Get validators for a specific preset configuration.

        Args:
            preset: The security preset to use

        Returns:
            List of configured validators, ordered by computational cost
        """
        if preset == ValidatorPreset.MINIMAL:
            return cls._get_minimal_validators()
        elif preset == ValidatorPreset.STANDARD:
            return cls._get_standard_validators()
        elif preset == ValidatorPreset.MAXIMUM:
            return cls._get_maximum_validators()
        elif preset == ValidatorPreset.STRICT:
            return cls._get_strict_validators()
        else:
            return []

    @classmethod
    def _get_minimal_validators(cls) -> List[TrustValidator]:
        """
        Minimal preset: Only critical, fast validators.

        Suitable for:
        - Low-risk applications
        - Performance-critical scenarios
        - Development/testing
        """
        validators = [
            cls._VALIDATOR_CLASSES["prompt_injection"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["sensitive_info"](
                on_fail=OnFailAction.EXCEPTION,
            ),
        ]
        return cls._sort_by_cost(validators)

    @classmethod
    def _get_standard_validators(cls) -> List[TrustValidator]:
        """
        Standard preset: Balanced security and performance.

        Suitable for:
        - Most production applications
        - General-purpose LLM applications
        - Balanced risk/performance trade-off
        """
        validators = [
            cls._VALIDATOR_CLASSES["prompt_injection"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["sensitive_info"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["system_prompt_leak"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["output_handling"](
                on_fail=OnFailAction.FILTER,
            ),
            cls._VALIDATOR_CLASSES["resource_consumption"](
                on_fail=OnFailAction.WARN,
            ),
        ]
        return cls._sort_by_cost(validators)

    @classmethod
    def _get_maximum_validators(cls) -> List[TrustValidator]:
        """
        Maximum preset: All validators enabled (defense-in-depth).

        Suitable for:
        - High-risk applications
        - Sensitive data handling
        - Compliance requirements
        - Maximum security posture
        """
        validators = [
            cls._VALIDATOR_CLASSES["prompt_injection"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["sensitive_info"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["system_prompt_leak"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["output_handling"](
                on_fail=OnFailAction.FILTER,
            ),
            cls._VALIDATOR_CLASSES["resource_consumption"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["supply_chain"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["excessive_agency"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["data_poisoning"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["embedding_security"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["misinformation"](
                on_fail=OnFailAction.WARN,
            ),
        ]
        return cls._sort_by_cost(validators)

    @classmethod
    def _get_strict_validators(cls) -> List[TrustValidator]:
        """
        Strict preset: All validators including legacy (maximum security).

        Suitable for:
        - Maximum security scenarios
        - Intellectual property protection
        - High-risk or high-stakes applications
        - Defense-in-depth with legacy coverage
        """
        validators = [
            # Modern validators (OWASP 2025)
            cls._VALIDATOR_CLASSES["prompt_injection"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["sensitive_info"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["system_prompt_leak"](
                on_fail=OnFailAction.EXCEPTION,
            ),
            cls._VALIDATOR_CLASSES["output_handling"](
                on_fail=OnFailAction.FILTER,
            ),
            cls._VALIDATOR_CLASSES["resource_consumption"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["supply_chain"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["excessive_agency"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["data_poisoning"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["embedding_security"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["misinformation"](
                on_fail=OnFailAction.WARN,
            ),
            # Legacy validators (OWASP 2023) - additional protection
            cls._VALIDATOR_CLASSES["insecure_plugin"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["overreliance"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["model_dos"](
                on_fail=OnFailAction.WARN,
            ),
            cls._VALIDATOR_CLASSES["model_theft"](
                on_fail=OnFailAction.WARN,
            ),
        ]
        return cls._sort_by_cost(validators)

    @classmethod
    def _sort_by_cost(cls, validators: List[TrustValidator]) -> List[TrustValidator]:
        """
        Sort validators by computational cost (fast first).

        This ensures that:
        1. Fast validators run first (early rejection)
        2. Expensive validators only run if fast ones pass
        3. Overall latency is minimized
        """

        def get_cost(validator: TrustValidator) -> int:
            # Find validator name by matching class
            for name, validator_class in cls._VALIDATOR_CLASSES.items():
                if isinstance(validator, validator_class):
                    return cls._VALIDATOR_COSTS.get(name, 999)
            return 999  # Unknown validators run last

        return sorted(validators, key=get_cost)

    @classmethod
    def create_custom(
        cls,
        validator_names: List[str],
        on_fail_map: Optional[Dict[str, OnFailAction]] = None,
    ) -> List[TrustValidator]:
        """
        Create a custom validator configuration.

        Args:
            validator_names: List of validator names to enable
            on_fail_map: Optional mapping of validator name to failure action

        Returns:
            List of configured validators, ordered by cost

        Example:
            validators = ValidatorRegistry.create_custom(
                validator_names=["prompt_injection", "sensitive_info", "data_poisoning"],
                on_fail_map={
                    "prompt_injection": OnFailAction.EXCEPTION,
                    "sensitive_info": OnFailAction.EXCEPTION,
                    "data_poisoning": OnFailAction.WARN,
                }
            )
        """
        on_fail_map = on_fail_map or {}
        validators = []

        for name in validator_names:
            if name not in cls._VALIDATOR_CLASSES:
                print(f"⚠️  Unknown validator: {name}, skipping")
                continue

            validator_class = cls._VALIDATOR_CLASSES[name]
            on_fail = on_fail_map.get(name, OnFailAction.WARN)

            validators.append(
                validator_class(
                    on_fail=on_fail,
                )
            )

        return cls._sort_by_cost(validators)

    @classmethod
    def list_available(cls) -> List[Dict[str, Any]]:
        """
        List all available validators with metadata.

        Returns:
            List of dicts with validator information
        """
        validators_info = []
        for name, validator_class in cls._VALIDATOR_CLASSES.items():
            validators_info.append(
                {
                    "name": name,
                    "class": validator_class.__name__,
                    "cost": cls._VALIDATOR_COSTS.get(name, 999),
                    "description": validator_class.__doc__ or "No description",
                }
            )

        # Sort by cost for display
        validators_info.sort(key=lambda x: x["cost"])
        return validators_info


if __name__ == "__main__":
    """Test the validator registry."""
    print("=" * 70)
    print("Validator Registry Demo")
    print("=" * 70)

    # Show available validators
    print("\n📋 Available Validators (sorted by cost):")
    print("-" * 70)
    for info in ValidatorRegistry.list_available():
        print(f"{info['cost']:2d} | {info['name']:25s} | {info['class']}")

    # Show presets
    print("\n🎛️  Validator Presets:")
    print("-" * 70)

    for preset in [
        ValidatorPreset.MINIMAL,
        ValidatorPreset.STANDARD,
        ValidatorPreset.MAXIMUM,
        ValidatorPreset.STRICT,
    ]:
        validators = ValidatorRegistry.get_preset(preset)
        print(f"\n{preset.value.upper()}:")
        print(f"  Count: {len(validators)}")
        print(f"  Validators: {[v.__class__.__name__ for v in validators]}")

    # Custom configuration
    print("\n🔧 Custom Configuration Example:")
    print("-" * 70)
    custom = ValidatorRegistry.create_custom(
        validator_names=["prompt_injection", "data_poisoning", "misinformation"],
        on_fail_map={
            "prompt_injection": OnFailAction.EXCEPTION,
            "data_poisoning": OnFailAction.WARN,
            "misinformation": OnFailAction.WARN,
        },
    )
    print(f"Custom validators: {[v.__class__.__name__ for v in custom]}")

    print("\n" + "=" * 70)
