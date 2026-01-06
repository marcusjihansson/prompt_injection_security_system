from unittest.mock import Mock

import pytest

from trust.guards.output_guard import OutputGuard, OutputViolationType


def test_pattern_based_output_guard_safe():
    guard = OutputGuard(use_llm=False)
    result = guard.validate("This is safe text.")
    assert result.is_safe == True
    assert result.violation_type == OutputViolationType.BENIGN


def test_pattern_based_output_guard_unsafe():
    guard = OutputGuard(use_llm=False)
    result = guard.validate("Here is my api_key: sk-12345678901234567890")
    assert result.is_safe == False
    assert "pii_exposure" in result.violation_details


def test_llm_powered_output_guard_mock():
    mock_llm = Mock()
    mock_llm.check.return_value = Mock(is_safe=False, violation_type=OutputViolationType.JAILBREAK)
    guard = OutputGuard(use_llm=True)
    guard.llm_guard.predictor = mock_llm
    result = guard.validate("Jailbreak attempt")
    assert result.is_safe == False
