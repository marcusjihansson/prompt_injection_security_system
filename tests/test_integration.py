"""
Integration tests for the complete threat detection pipeline.

These tests verify end-to-end functionality across multiple components.
"""

import os
from unittest.mock import Mock, patch

import dspy
import pytest

# Import modules to test
from trust import (
    OutputGuard,
    ProductionThreatDetector,
    RegexBaseline,
    SelfLearningShield,
    ThreatDetector,
    ThreatType,
    Trust,
    TrustedLayer,
)


class TestEndToEndPipeline:
    """Test the complete threat detection pipeline from input to output."""

    def test_trust_wrapper_integration(self):
        """Test Trust wrapper with a mock DSPy module."""

        # Create a simple mock module
        mock_module = Mock()
        mock_module.forward = Mock(return_value=dspy.Prediction(answer="Safe response"))

        # Wrap with Trust
        with patch("trust.trust.ProductionThreatDetector") as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.detect_threat = Mock(
                return_value={"is_threat": False, "threat_type": None}
            )
            mock_detector.return_value = mock_detector_instance

            trusted_module = Trust(mock_module)

            # Test with safe input
            result = trusted_module.forward("What is 2+2?")
            # Result is from process_request which returns a dict from shield.predict
            assert result is not None

    def test_threat_detection_with_regex_fusion(self):
        """Test threat detection using both regex and LLM."""

        # Create components
        regex_baseline = RegexBaseline()

        # Test known malicious patterns
        sql_injection = "'; DROP TABLE users; --"
        result = regex_baseline.check(sql_injection)

        # Check threats were detected
        assert len(result.threats) > 0
        assert result.severity > 0
        # result is RegexResult object

    def test_multi_layer_defense(self):
        """Test multi-layered defense with input and output guards."""

        # Setup mocks
        mock_input_guard = Mock(return_value={"is_threat": False})
        mock_core_logic = Mock(return_value="Safe response")
        mock_output_guard = Mock()
        mock_output_guard.validate.return_value = Mock(is_safe=True, violations=[])

        shield = SelfLearningShield(
            input_guard=mock_input_guard,
            core_logic=mock_core_logic,
            output_guard=mock_output_guard,
        )

        result = shield.predict("What is the capital of France?")
        assert result["is_trusted"] is True


class TestProductionDeployment:
    """Test production deployment scenarios."""

    def test_production_detector_initialization(self):
        """Test ProductionThreatDetector can be initialized."""

        with patch("trust.production.detector.RegexBaseline"):
            with patch("trust.production.detector.security_model"):
                with patch("trust.production.detector.OutputGuard"):
                    with patch("trust.production.detector.SemanticCache"):
                        with patch("trust.production.detector.RequestDeduplicator"):
                            detector = ProductionThreatDetector(enable_regex_baseline=False)

                            assert detector is not None
                            assert hasattr(detector, "detect_threat")

    def test_caching_integration(self):
        """Test semantic cache integration."""

        from trust import SemanticCache

        # Create cache
        cache = SemanticCache(similarity_threshold=0.95)

        # Test cache operations
        test_input = "Is this a safe query?"
        test_result = {"is_threat": False, "confidence": 0.99}

        # Store in cache
        cache.set(test_input, test_result)

        # Retrieve from cache (exact match)
        cached = cache.get(test_input)
        assert cached is not None
        assert cached["is_threat"] is False

    def test_request_deduplication(self):
        """Test request deduplication."""

        from trust import RequestDeduplicator

        # Create deduplicator (no arguments needed)
        dedup = RequestDeduplicator()

        # Verify it has the expected attributes
        assert hasattr(dedup, "pending")
        assert hasattr(dedup, "execute")

        # Test basic functionality - it's an async deduplicator
        import asyncio

        async def test_async():
            result = await dedup.execute("test", lambda: {"result": "ok"})
            assert result is not None

        # Run the async test
        asyncio.run(test_async())


class TestChainOfTrustIntegration:
    """Test Chain of Trust components working together."""

    def test_trusted_layer_with_output_guard(self):
        """Test TrustedLayer with OutputGuard."""

        from trust import OutputGuard

        # Create output guard
        output_guard = OutputGuard(use_llm=False)

        # Test safe output
        safe_output = "The capital of France is Paris."
        result = output_guard.validate(safe_output, "User input", "System context")

        assert result.is_safe is True

    def test_failure_logging_for_retraining(self):
        """Test that failures are logged for retraining."""

        # Setup simple mocks
        mock_input = Mock(return_value={"is_threat": False})
        mock_core = Mock(return_value="Bad output")
        mock_output = Mock()
        mock_output.validate.return_value = Mock(
            is_safe=False, violation_type="content", violation_details="bad"
        )

        shield = SelfLearningShield(mock_input, mock_core, mock_output)

        # Check that failures list exists
        assert hasattr(shield, "new_failures")
        assert isinstance(shield.new_failures, list)

        # Run prediction to trigger failure
        shield.predict("input")
        assert len(shield.new_failures) > 0


class TestErrorHandlingAndRecovery:
    """Test error handling and recovery mechanisms."""

    def test_graceful_degradation_on_llm_failure(self):
        """Test system degrades gracefully when LLM fails."""

        with patch("trust.production.detector.RegexBaseline") as mock_regex:
            with patch("trust.production.detector.security_model") as mock_model:
                # Setup regex to work
                mock_regex_instance = Mock()
                mock_regex_instance.check = Mock(return_value=Mock(severity=0, threats=[]))
                mock_regex.return_value = mock_regex_instance

                # Setup LLM to fail
                mock_model_instance = Mock()
                mock_model_instance.predict = Mock(side_effect=Exception("LLM Error"))
                mock_model.return_value = mock_model_instance

                detector = ProductionThreatDetector(enable_regex_baseline=True)

                result = detector.detect_threat("Test input")

                assert "is_threat" in result
                assert result["is_threat"] is False

    def test_invalid_input_handling(self):
        """Test handling of invalid inputs."""

        regex_baseline = RegexBaseline()

        # Test empty input
        result = regex_baseline.check("")
        assert hasattr(result, "threats")
        assert hasattr(result, "severity")

        # Test None input
        with pytest.raises((TypeError, AttributeError)):
            regex_baseline.check(None)  # type: ignore


class TestPerformanceOptimizations:
    """Test performance optimization features."""

    def test_parallel_execution(self):
        """Test that parallel execution is used when available."""

        with patch(
            "trust.guards.input_guard.concurrent.futures.ThreadPoolExecutor"
        ) as mock_executor:
            # Setup mocks
            mock_input = Mock(return_value={"is_threat": False})
            mock_core = Mock(return_value="Safe")
            mock_output = Mock()
            mock_output.validate.return_value = Mock(is_safe=True)

            # Mock executor
            mock_future = Mock()
            mock_future.result = Mock(return_value={"is_threat": False})
            mock_executor.return_value.__enter__.return_value.submit = Mock(
                return_value=mock_future
            )

            shield = SelfLearningShield(mock_input, mock_core, mock_output, parallel_execution=True)
            result = shield.predict("Test input")

            assert "is_trusted" in result
            assert mock_executor.return_value.__enter__.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
