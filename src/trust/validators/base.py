from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union


class OnFailAction(Enum):
    """What to do when validation fails."""

    EXCEPTION = "exception"  # Raise error, stop execution
    RECOMPILE = "recompile"  # Trigger DSPy recompilation
    FIX = "fix"  # Use validator's fix_value
    FILTER = "filter"  # Remove invalid parts
    WARN = "warn"  # Log warning, continue
    FALLBACK = "fallback"  # Use fallback module
    NOOP = "noop"  # Just record, do nothing


@dataclass
class TrustResult:
    """Result from trust validation."""

    outcome: Literal["pass", "fail"]
    validator_name: str

    # Failure information
    error_message: Optional[str] = None
    fix_value: Optional[Any] = None

    # Rich context
    metadata: Dict[str, Any] = None
    score: Optional[float] = None

    # DSPy-specific
    failed_at_step: Optional[int] = None  # Which step in chain failed
    reasoning_trace: Optional[List[str]] = None  # For CoT validation

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TrustValidator(ABC):
    """Base class for all trust validators."""

    # Class-level registration
    _registry: Dict[str, type] = {}

    def __init__(
        self,
        on_fail: OnFailAction = OnFailAction.EXCEPTION,
        enabled: bool = True,
        tags: Optional[List[str]] = None,
    ):
        self.on_fail = on_fail
        self.enabled = enabled
        self.tags = tags or []
        self._resources = None  # Lazy-loaded resources

    def __init_subclass__(cls, **kwargs):
        """Auto-register validators."""
        super().__init_subclass__(**kwargs)
        if not cls.__name__.startswith("_"):  # Skip abstract classes
            TrustValidator._registry[cls.__name__] = cls

    @abstractmethod
    def validate(
        self,
        value: Any,
        metadata: Dict[str, Any],
    ) -> TrustResult:
        """Validate a value.

        Args:
            value: The value to validate (could be string, dict, etc.)
            metadata: Context including:
                - prompt: The input prompt
                - full_output: Complete LLM output
                - module_name: Which DSPy module produced this
                - step: Which step in the chain (for CoT, etc.)
                - signature: The DSPy signature
                - examples: Few-shot examples used

        Returns:
            TrustResult with outcome and metadata
        """
        pass

    def validate_stream(
        self,
        chunk: str,
        accumulated: str,
        metadata: Dict[str, Any],
    ) -> Optional[TrustResult]:
        """Validate streaming output (optional).

        Args:
            chunk: New chunk received
            accumulated: All chunks so far
            metadata: Same as validate()

        Returns:
            None if validation should continue,
            TrustResult if validation can conclude
        """
        # Default: wait for complete output
        return None

    def get_fix(
        self,
        value: Any,
        metadata: Dict[str, Any],
    ) -> Optional[Any]:
        """Provide automatic fix for failed validation.

        Returns:
            Fixed value, or None if no fix available
        """
        return None

    @property
    def name(self) -> str:
        """Validator name for registry."""
        return self.__class__.__name__

    @classmethod
    def from_hub(cls, uri: str, **kwargs) -> "TrustValidator":
        """Load validator from hub.

        Args:
            uri: Hub URI like "trust://validators/factuality"
            **kwargs: Validator-specific parameters
        """
        # Implementation would download and instantiate
        pass
