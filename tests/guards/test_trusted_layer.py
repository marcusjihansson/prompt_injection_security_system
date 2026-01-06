from unittest.mock import Mock

import pytest

from trust.guards.trusted_layer import TrustedLayer


def test_trusted_layer_success():
    mock_target = Mock()
    mock_target.return_value = {"reasoning": "Good", "capital": "Paris"}
    mock_auditor = Mock()
    mock_auditor.return_value = Mock(is_valid="True", critique="OK")

    layer = TrustedLayer(mock_target, max_retries=0)
    layer.auditor = mock_auditor
    result = layer.forward(country="France")
    assert result["trust_verified"] == True


def test_trusted_layer_retry():
    mock_target = Mock()
    mock_target.return_value = {"reasoning": "Wrong", "capital": "Berlin"}
    mock_auditor = Mock()
    mock_auditor.side_effect = [
        Mock(is_valid="False", critique="Wrong capital"),
        Mock(is_valid="True", critique="Fixed"),
    ]

    layer = TrustedLayer(mock_target, max_retries=1)
    layer.auditor = mock_auditor
    result = layer.forward(country="France")
    assert mock_target.call_count == 2  # Initial + retry
    assert result["trust_verified"] == True


def test_trusted_layer_max_retries():
    mock_target = Mock(return_value={"reasoning": "Bad", "capital": "Berlin"})
    mock_auditor = Mock(return_value=Mock(is_valid="False", critique="Always bad"))

    layer = TrustedLayer(mock_target, max_retries=1)
    layer.auditor = mock_auditor
    result = layer.forward(country="France")
    assert result["trust_verified"] == False
