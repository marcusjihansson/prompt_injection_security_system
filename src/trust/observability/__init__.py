"""
Observability components for distributed tracing and monitoring.

Includes:
- OpenTelemetry distributed tracing
- Prometheus metrics
- Correlation IDs
- Structured logging
"""

from trust.observability.metrics import MetricsCollector, get_metrics_collector
from trust.observability.tracing import get_tracer, init_tracing, trace_detector, trace_function

__all__ = [
    # Tracing
    "init_tracing",
    "get_tracer",
    "trace_function",
    "trace_detector",
    # Metrics
    "MetricsCollector",
    "get_metrics_collector",
]
