"""
Input validation and sanitization for API requests.

Prevents:
- Injection attacks
- Excessively large inputs
- Invalid characters
- DoS via malformed input
"""

import html
import logging
import re
from typing import Optional

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class InputValidator:
    """
    Input validation for API requests.

    Validates and sanitizes user input to prevent attacks.
    """

    def __init__(
        self,
        max_length: int = 10000,
        allow_html: bool = False,
        allow_special_chars: bool = True,
    ):
        """
        Initialize input validator.

        Args:
            max_length: Maximum input length in characters
            allow_html: Whether to allow HTML tags
            allow_special_chars: Whether to allow special characters
        """
        self.max_length = max_length
        self.allow_html = allow_html
        self.allow_special_chars = allow_special_chars

        # Dangerous patterns to detect
        self.dangerous_patterns = [
            r"<script[^>]*>.*?</script>",  # Script tags
            r"javascript:",  # JavaScript protocol
            r"on\w+\s*=",  # Event handlers (onclick, onerror, etc)
            r"eval\s*\(",  # eval() calls
            r"expression\s*\(",  # CSS expressions
        ]

        logger.info(
            f"✅ InputValidator initialized: max_length={max_length}, " f"allow_html={allow_html}"
        )

    def validate(self, text: str, field_name: str = "input") -> str:
        """
        Validate and sanitize input text.

        Args:
            text: Input text to validate
            field_name: Name of field (for error messages)

        Returns:
            Sanitized text

        Raises:
            HTTPException: If validation fails
        """
        # Check for None or empty
        if text is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} cannot be None",
            )

        # Check length
        if len(text) > self.max_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} exceeds maximum length of {self.max_length}",
            )

        if len(text) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} cannot be empty",
            )

        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected in {field_name}: {pattern}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field_name} contains potentially malicious content",
                )

        # Sanitize HTML if not allowed
        if not self.allow_html:
            text = html.escape(text)

        # Check for control characters
        if not self.allow_special_chars:
            # Remove control characters except whitespace
            text = "".join(char for char in text if char.isprintable() or char.isspace())

        return text

    def validate_length(
        self, text: str, min_length: int = 1, max_length: Optional[int] = None
    ) -> bool:
        """
        Validate text length.

        Args:
            text: Text to validate
            min_length: Minimum length
            max_length: Maximum length (uses instance default if None)

        Returns:
            True if valid

        Raises:
            HTTPException: If length invalid
        """
        if max_length is None:
            max_length = self.max_length

        if len(text) < min_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Input must be at least {min_length} characters",
            )

        if len(text) > max_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Input must not exceed {max_length} characters",
            )

        return True

    def check_encoding(self, text: str) -> bool:
        """
        Check for valid UTF-8 encoding.

        Args:
            text: Text to check

        Returns:
            True if valid UTF-8

        Raises:
            HTTPException: If invalid encoding
        """
        try:
            text.encode("utf-8")
            return True
        except UnicodeEncodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid text encoding (must be UTF-8)",
            )


def sanitize_input(text: str, max_length: int = 10000) -> str:
    """
    Quick sanitization function for input text.

    Args:
        text: Text to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized text

    Raises:
        HTTPException: If validation fails
    """
    validator = InputValidator(max_length=max_length)
    return validator.validate(text)


def validate_batch_size(size: int, max_size: int = 100):
    """
    Validate batch request size.

    Args:
        size: Number of items in batch
        max_size: Maximum allowed batch size

    Raises:
        HTTPException: If batch too large
    """
    if size > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {size} exceeds maximum of {max_size}",
        )

    if size <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size must be positive",
        )


class RequestValidator:
    """
    Validator for complete API requests.
    """

    @staticmethod
    def validate_detect_request(text: str, max_length: int = 10000) -> str:
        """
        Validate /detect request.

        Args:
            text: Input text
            max_length: Maximum text length

        Returns:
            Validated text
        """
        validator = InputValidator(max_length=max_length, allow_html=False)
        return validator.validate(text, field_name="text")

    @staticmethod
    def validate_batch_request(
        texts: list, max_batch_size: int = 100, max_text_length: int = 10000
    ):
        """
        Validate batch detection request.

        Args:
            texts: List of input texts
            max_batch_size: Maximum batch size
            max_text_length: Maximum length per text

        Raises:
            HTTPException: If validation fails
        """
        validate_batch_size(len(texts), max_batch_size)

        validator = InputValidator(max_length=max_text_length, allow_html=False)

        # Validate each text
        for i, text in enumerate(texts):
            try:
                validator.validate(text, field_name=f"texts[{i}]")
            except HTTPException as e:
                # Re-raise with batch context
                raise HTTPException(
                    status_code=e.status_code,
                    detail=f"Validation error in batch item {i}: {e.detail}",
                )


# Global validator instance
_input_validator: Optional[InputValidator] = None


def get_input_validator() -> InputValidator:
    """Get global input validator instance."""
    global _input_validator
    if _input_validator is None:
        _input_validator = InputValidator()
    return _input_validator
