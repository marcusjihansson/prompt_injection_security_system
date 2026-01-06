"""
Prometheus metrics collection for monitoring.

Metrics tracked:
- Request counts and rates
- Detection latency (histograms)
- Threat detection rates
- Cache hit rates
- Error rates
"""

import logging
import time
from typing import Dict, Optional

from prometheus_client import REGISTRY, Counter, Gauge, Histogram, Info, generate_latest

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Prometheus metrics collector for threat detection system.

    Collects and exposes metrics for monitoring and alerting.
    """

    def __init__(self, namespace: str = "threat_detection"):
        """
        Initialize metrics collector.

        Args:
            namespace: Metric namespace prefix
        """
        self.namespace = namespace

        # Request metrics
        self.requests_total = Counter(
            f"{namespace}_requests_total",
            "Total number of detection requests",
            ["endpoint", "method", "status"],
        )

        self.requests_in_progress = Gauge(
            f"{namespace}_requests_in_progress",
            "Number of requests currently being processed",
            ["endpoint"],
        )

        # Detection metrics
        self.detections_total = Counter(
            f"{namespace}_detections_total",
            "Total number of threat detections",
            ["threat_type", "detection_method"],
        )

        self.threats_blocked = Counter(
            f"{namespace}_threats_blocked_total",
            "Total number of threats blocked",
            ["threat_type"],
        )

        # Latency metrics (histograms)
        self.request_duration = Histogram(
            f"{namespace}_request_duration_seconds",
            "Request duration in seconds",
            ["endpoint", "method"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
        )

        self.detection_duration = Histogram(
            f"{namespace}_detection_duration_seconds",
            "Detection duration in seconds",
            ["detection_method"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        )

        # Cache metrics
        self.cache_hits = Counter(
            f"{namespace}_cache_hits_total",
            "Total cache hits",
            ["cache_tier"],  # L1, L2, L3
        )

        self.cache_misses = Counter(
            f"{namespace}_cache_misses_total",
            "Total cache misses",
        )

        self.cache_size = Gauge(
            f"{namespace}_cache_size_bytes",
            "Current cache size in bytes",
            ["cache_tier"],
        )

        # Fast-path metrics
        self.fast_path_requests = Counter(
            f"{namespace}_fast_path_requests_total",
            "Requests handled by fast-path",
            ["result"],  # safe, threat
        )

        self.slow_path_requests = Counter(
            f"{namespace}_slow_path_requests_total",
            "Requests requiring full LLM analysis",
        )

        # Authentication metrics
        self.auth_attempts = Counter(
            f"{namespace}_auth_attempts_total",
            "Authentication attempts",
            ["method", "result"],  # api_key/jwt, success/failure
        )

        # Rate limiting metrics
        self.rate_limit_exceeded = Counter(
            f"{namespace}_rate_limit_exceeded_total",
            "Rate limit violations",
            ["endpoint"],
        )

        # Error metrics
        self.errors_total = Counter(
            f"{namespace}_errors_total",
            "Total errors",
            ["error_type", "endpoint"],
        )

        # System info
        self.system_info = Info(
            f"{namespace}_system",
            "System information",
        )

        # Set system info
        self.system_info.info(
            {
                "version": "2.0.0",
                "service": "threat-detection-system",
            }
        )

        logger.info(f"✅ MetricsCollector initialized: namespace={namespace}")

    def record_request(
        self,
        endpoint: str,
        method: str,
        status: str,
        duration: float,
    ):
        """
        Record an API request.

        Args:
            endpoint: API endpoint
            method: HTTP method
            status: Response status (success, error, blocked)
            duration: Request duration in seconds
        """
        self.requests_total.labels(
            endpoint=endpoint,
            method=method,
            status=status,
        ).inc()

        self.request_duration.labels(
            endpoint=endpoint,
            method=method,
        ).observe(duration)

    def record_detection(
        self,
        threat_type: str,
        detection_method: str,
        duration: float,
        is_threat: bool,
    ):
        """
        Record a threat detection.

        Args:
            threat_type: Type of threat detected
            detection_method: Method used (fast_path, slow_path, etc.)
            duration: Detection duration in seconds
            is_threat: Whether a threat was detected
        """
        self.detections_total.labels(
            threat_type=threat_type,
            detection_method=detection_method,
        ).inc()

        self.detection_duration.labels(
            detection_method=detection_method,
        ).observe(duration)

        if is_threat:
            self.threats_blocked.labels(threat_type=threat_type).inc()

    def record_cache_hit(self, cache_tier: str):
        """
        Record a cache hit.

        Args:
            cache_tier: Cache tier (L1, L2, L3)
        """
        self.cache_hits.labels(cache_tier=cache_tier).inc()

    def record_cache_miss(self):
        """Record a cache miss."""
        self.cache_misses.inc()

    def update_cache_size(self, cache_tier: str, size_bytes: int):
        """
        Update cache size metric.

        Args:
            cache_tier: Cache tier (L1, L2, L3)
            size_bytes: Cache size in bytes
        """
        self.cache_size.labels(cache_tier=cache_tier).set(size_bytes)

    def record_fast_path(self, result: str):
        """
        Record fast-path request.

        Args:
            result: Result (safe, threat)
        """
        self.fast_path_requests.labels(result=result).inc()

    def record_slow_path(self):
        """Record slow-path request."""
        self.slow_path_requests.inc()

    def record_auth_attempt(self, method: str, success: bool):
        """
        Record authentication attempt.

        Args:
            method: Auth method (api_key, jwt)
            success: Whether auth succeeded
        """
        result = "success" if success else "failure"
        self.auth_attempts.labels(method=method, result=result).inc()

    def record_rate_limit_exceeded(self, endpoint: str):
        """
        Record rate limit violation.

        Args:
            endpoint: API endpoint
        """
        self.rate_limit_exceeded.labels(endpoint=endpoint).inc()

    def record_error(self, error_type: str, endpoint: str):
        """
        Record an error.

        Args:
            error_type: Type of error
            endpoint: API endpoint
        """
        self.errors_total.labels(
            error_type=error_type,
            endpoint=endpoint,
        ).inc()

    def start_request(self, endpoint: str):
        """
        Mark request as in progress.

        Args:
            endpoint: API endpoint
        """
        self.requests_in_progress.labels(endpoint=endpoint).inc()

    def end_request(self, endpoint: str):
        """
        Mark request as complete.

        Args:
            endpoint: API endpoint
        """
        self.requests_in_progress.labels(endpoint=endpoint).dec()

    def get_metrics(self) -> bytes:
        """
        Get Prometheus metrics in text format.

        Returns:
            Metrics in Prometheus text format
        """
        return generate_latest(REGISTRY)


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def init_metrics_collector(namespace: str = "threat_detection") -> MetricsCollector:
    """
    Initialize global metrics collector.

    Args:
        namespace: Metric namespace

    Returns:
        MetricsCollector instance
    """
    global _metrics_collector
    _metrics_collector = MetricsCollector(namespace=namespace)
    return _metrics_collector


# Context manager for timing operations
class timed_operation:
    """
    Context manager for timing operations and recording metrics.

    Usage:
        with timed_operation("detect", metrics_collector):
            result = detector.detect(text)
    """

    def __init__(
        self,
        operation_name: str,
        metrics_collector: Optional[MetricsCollector] = None,
        labels: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize timed operation.

        Args:
            operation_name: Name of operation
            metrics_collector: Optional metrics collector
            labels: Optional metric labels
        """
        self.operation_name = operation_name
        self.metrics_collector = metrics_collector or get_metrics_collector()
        self.labels = labels or {}
        self.start_time = None

    def __enter__(self):
        """Start timing."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and record metric."""
        if self.start_time:
            duration = time.time() - self.start_time

            # Record based on operation type
            if self.operation_name.startswith("detect"):
                detection_method = self.labels.get("detection_method", "unknown")
                threat_type = self.labels.get("threat_type", "benign")
                is_threat = self.labels.get("is_threat", False)

                self.metrics_collector.record_detection(
                    threat_type=threat_type,
                    detection_method=detection_method,
                    duration=duration,
                    is_threat=is_threat,
                )
