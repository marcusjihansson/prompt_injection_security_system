from unittest.mock import Mock

import pytest

from trust.guards.input_guard import SelfLearningShield


def test_self_learning_shield_safe():
    mock_input_guard = Mock(return_value={"is_threat": False})
    mock_core_logic = Mock(return_value="Safe response")
    mock_output_guard = Mock()
    mock_output_guard.validate.return_value = Mock(is_safe=True)

    shield = SelfLearningShield(mock_input_guard, mock_core_logic, mock_output_guard)
    result = shield.predict("Safe input")
    assert result["is_trusted"] == True
    assert len(shield.new_failures) == 0


def test_self_learning_shield_failure():
    mock_input_guard = Mock(return_value={"is_threat": False})
    mock_core_logic = Mock(return_value="Unsafe response")
    mock_output_guard = Mock()
    mock_output_guard.validate.return_value = Mock(
        is_safe=False, violation_type="jailbreak", violation_details="Bad"
    )

    shield = SelfLearningShield(mock_input_guard, mock_core_logic, mock_output_guard)
    result = shield.predict("Unsafe input")
    assert result["is_trusted"] == False
    assert len(shield.new_failures) == 1


def test_self_learning_shield_learn():
    shield = SelfLearningShield(Mock(), Mock(), Mock())
    shield.new_failures = ["fake_failure"]
    shield.learn()
    assert len(shield.new_failures) == 0
