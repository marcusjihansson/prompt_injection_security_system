"""
Middleware for observability: correlation IDs, tracing, and metrics.
"""

import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.middleware.base import BaseHTTPMiddleware

from trust.observability.metrics import get_metrics_collector
from trust.observability.tracing import get_correlation_id, set_correlation_id

logger = logging.getLogger(__name__)


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add correlation IDs to all requests.

    Extracts or generates a correlation ID and adds it to:
    - Request context
    - Response headers
    - Trace spans
    - Logs
    """

    def __init__(self, app, header_name: str = "X-Correlation-ID"):
        """
        Initialize correlation ID middleware.

        Args:
            app: FastAPI application
            header_name: HTTP header name for correlation ID
        """
        super().__init__(app)
        self.header_name = header_name
        logger.info(f"✅ CorrelationIDMiddleware initialized: header={header_name}")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Add correlation ID to request.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response with correlation ID header
        """
        # Extract or generate correlation ID
        correlation_id = request.headers.get(self.header_name, str(uuid.uuid4()))

        # Set in context variable
        set_correlation_id(correlation_id)

        # Add to request state
        request.state.correlation_id = correlation_id

        # Add to current span if tracing enabled
        current_span = trace.get_current_span()
        if current_span.is_recording():
            current_span.set_attribute("correlation_id", correlation_id)

        # Process request
        response = await call_next(request)

        # Add correlation ID to response headers
        response.headers[self.header_name] = correlation_id

        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware to collect Prometheus metrics for all requests.
    """

    def __init__(self, app):
        """
        Initialize metrics middleware.

        Args:
            app: FastAPI application
        """
        super().__init__(app)
        self.metrics_collector = get_metrics_collector()
        logger.info("✅ MetricsMiddleware initialized")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Collect metrics for request.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        # Extract endpoint info
        endpoint = request.url.path
        method = request.method

        # Mark request as in progress
        self.metrics_collector.start_request(endpoint)

        # Time request
        start_time = time.time()
        status = "success"

        try:
            response = await call_next(request)

            # Determine status
            if response.status_code >= 500:
                status = "error"
            elif response.status_code == 429:
                status = "rate_limited"
                self.metrics_collector.record_rate_limit_exceeded(endpoint)
            elif response.status_code >= 400:
                status = "client_error"

            return response

        except Exception as e:
            status = "error"
            self.metrics_collector.record_error(
                error_type=type(e).__name__,
                endpoint=endpoint,
            )
            raise

        finally:
            # Record metrics
            duration = time.time() - start_time
            self.metrics_collector.record_request(
                endpoint=endpoint,
                method=method,
                status=status,
                duration=duration,
            )
            self.metrics_collector.end_request(endpoint)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured request/response logging.
    """

    def __init__(self, app):
        """
        Initialize logging middleware.

        Args:
            app: FastAPI application
        """
        super().__init__(app)
        logger.info("✅ LoggingMiddleware initialized")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Log request and response.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        # Get correlation ID
        correlation_id = getattr(request.state, "correlation_id", "unknown")

        # Log request
        logger.info(
            "Request started",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else "unknown",
            },
        )

        # Process request
        start_time = time.time()
        try:
            response = await call_next(request)
            duration_ms = (time.time() - start_time) * 1000

            # Log response
            logger.info(
                "Request completed",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )

            return response

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            # Log error
            logger.error(
                "Request failed",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "duration_ms": duration_ms,
                },
                exc_info=True,
            )
            raise


def instrument_fastapi(app, service_name: str = "threat-detection-system"):
    """
    Instrument FastAPI app with OpenTelemetry auto-instrumentation.

    Args:
        app: FastAPI application
        service_name: Service name for tracing
    """
    # Auto-instrument FastAPI
    FastAPIInstrumentor.instrument_app(app)
    logger.info(f"✅ FastAPI auto-instrumented: service={service_name}")


def add_observability_middleware(app):
    """
    Add all observability middleware to FastAPI app.

    Args:
        app: FastAPI application
    """
    # Add middleware in reverse order (they execute in LIFO order)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(CorrelationIDMiddleware)

    logger.info("✅ Observability middleware added")
