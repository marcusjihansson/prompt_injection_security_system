"""
Distributed tracing with OpenTelemetry.

Provides:
- Request correlation IDs
- Distributed tracing spans
- Performance instrumentation
- Error tracking
"""

import functools
import logging
import time
import uuid
from contextvars import ContextVar
from typing import Any, Callable, Dict, Optional

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

logger = logging.getLogger(__name__)

# Context variable for correlation ID
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


def init_tracing(
    service_name: str = "threat-detection-system",
    export_to_console: bool = False,
    otlp_endpoint: Optional[str] = None,
) -> TracerProvider:
    """
    Initialize OpenTelemetry tracing.

    Args:
        service_name: Name of the service
        export_to_console: Whether to export traces to console (dev)
        otlp_endpoint: OTLP collector endpoint (e.g., "http://localhost:4317")

    Returns:
        TracerProvider instance
    """
    # Create resource with service name
    resource = Resource(attributes={SERVICE_NAME: service_name})

    # Create tracer provider
    provider = TracerProvider(resource=resource)

    # Add exporters
    if export_to_console:
        # Console exporter for development
        console_exporter = ConsoleSpanExporter()
        provider.add_span_processor(BatchSpanProcessor(console_exporter))
        logger.info("✅ Console span exporter enabled")

    if otlp_endpoint:
        # OTLP exporter for production (Jaeger, Tempo, etc.)
        otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info(f"✅ OTLP span exporter enabled: {otlp_endpoint}")

    # Set as global tracer provider
    trace.set_tracer_provider(provider)

    logger.info(f"✅ Tracing initialized: service={service_name}")
    return provider


def get_tracer(name: str = __name__) -> trace.Tracer:
    """
    Get a tracer instance.

    Args:
        name: Tracer name (usually __name__)

    Returns:
        Tracer instance
    """
    return trace.get_tracer(name)


def get_correlation_id() -> str:
    """
    Get or create correlation ID for current request.

    Returns:
        Correlation ID string
    """
    correlation_id = correlation_id_var.get()
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
        correlation_id_var.set(correlation_id)
    return correlation_id


def set_correlation_id(correlation_id: str):
    """
    Set correlation ID for current request.

    Args:
        correlation_id: Correlation ID to set
    """
    correlation_id_var.set(correlation_id)


def trace_function(
    operation_name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None
):
    """
    Decorator to trace function execution.

    Usage:
        @trace_function("detect_threat")
        def detect_threat(text: str):
            ...

    Args:
        operation_name: Name of the operation (defaults to function name)
        attributes: Additional span attributes

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer(func.__module__)
            op_name = operation_name or func.__name__

            with tracer.start_as_current_span(op_name) as span:
                # Add correlation ID
                span.set_attribute("correlation_id", get_correlation_id())

                # Add custom attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)

                # Add function info
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)

                # Execute function
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("status", "success")
                    return result
                except Exception as e:
                    span.set_attribute("status", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    span.record_exception(e)
                    raise
                finally:
                    duration_ms = (time.time() - start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer(func.__module__)
            op_name = operation_name or func.__name__

            with tracer.start_as_current_span(op_name) as span:
                # Add correlation ID
                span.set_attribute("correlation_id", get_correlation_id())

                # Add custom attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)

                # Add function info
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)

                # Execute function
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("status", "success")
                    return result
                except Exception as e:
                    span.set_attribute("status", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    span.record_exception(e)
                    raise
                finally:
                    duration_ms = (time.time() - start_time) * 1000
                    span.set_attribute("duration_ms", duration_ms)

        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def trace_detector(
    detector_name: str,
    input_text: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
):
    """
    Create a span for threat detection.

    Args:
        detector_name: Name of the detector
        input_text: Input text (truncated)
        result: Detection result

    Returns:
        Context manager for span
    """
    tracer = get_tracer(__name__)
    span = tracer.start_span(f"detect.{detector_name}")

    # Add correlation ID
    span.set_attribute("correlation_id", get_correlation_id())

    # Add detector info
    span.set_attribute("detector.name", detector_name)

    # Add input info (truncated for privacy)
    if input_text:
        span.set_attribute("input.length", len(input_text))
        span.set_attribute("input.preview", input_text[:50])

    # Add result info
    if result:
        span.set_attribute("result.is_threat", result.get("is_threat", False))
        span.set_attribute("result.threat_type", result.get("threat_type", "unknown"))
        span.set_attribute("result.confidence", result.get("confidence", 0.0))
        if "detection_method" in result:
            span.set_attribute("result.detection_method", result["detection_method"])

    return span


# Import asyncio at module level for type checking
import asyncio
