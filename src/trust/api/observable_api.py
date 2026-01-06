"""
Observable FastAPI application with tracing and metrics.

Combines:
- Security features (auth, rate limiting, audit logging)
- Performance optimizations (caching, adaptive detection)
- Observability (tracing, metrics, correlation IDs)
"""

import logging
import time
from typing import List, Optional

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from trust.observability.metrics import get_metrics_collector
from trust.observability.middleware import add_observability_middleware, instrument_fastapi
from trust.observability.tracing import (
    get_correlation_id,
    init_tracing,
    trace_detector,
    trace_function,
)
from trust.production import EnhancedProductionThreatDetector
from trust.security.audit import SecurityEvent, get_audit_logger
from trust.security.auth import User, verify_authentication
from trust.security.headers import SecurityHeadersMiddleware, configure_cors
from trust.security.validation import RequestValidator

logger = logging.getLogger(__name__)


# Request/Response Models
class DetectionRequest(BaseModel):
    """Request model for threat detection."""

    text: str


class DetectionResponse(BaseModel):
    """Response model for threat detection."""

    is_threat: bool
    threat_type: str
    confidence: float
    reasoning: str
    detection_method: Optional[str] = None
    latency_ms: Optional[float] = None
    correlation_id: Optional[str] = None


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    version: str
    correlation_id: str


def create_observable_app(
    enable_tracing: bool = True,
    enable_metrics: bool = True,
    enable_security: bool = True,
    otlp_endpoint: Optional[str] = None,
) -> FastAPI:
    """
    Create FastAPI app with full observability.

    Args:
        enable_tracing: Enable OpenTelemetry tracing
        enable_metrics: Enable Prometheus metrics
        enable_security: Enable security features
        otlp_endpoint: Optional OTLP collector endpoint

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Observable Threat Detection API",
        version="2.0.0",
        description="Production-ready API with tracing, metrics, and security",
    )

    # Initialize tracing
    if enable_tracing:
        init_tracing(
            service_name="threat-detection-system",
            export_to_console=False,
            otlp_endpoint=otlp_endpoint,
        )
        instrument_fastapi(app)

    # Initialize metrics
    if enable_metrics:
        metrics_collector = get_metrics_collector()

    # Initialize audit logger
    audit_logger = get_audit_logger() if enable_security else None

    # Add observability middleware
    add_observability_middleware(app)

    # Add security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Configure CORS
    configure_cors(app)

    # Initialize detector
    detector = EnhancedProductionThreatDetector(
        enable_regex_baseline=True,
        enable_adaptive=True,
        enable_valkey=True,
        enable_connection_pool=True,
    )

    # Authentication dependency
    async def get_user(request: Request) -> User:
        """Get authenticated user or anonymous."""
        if not enable_security:
            return User(username="anonymous", roles=["user"])
        return await verify_authentication()

    @app.post("/v1/detect", response_model=DetectionResponse)
    @trace_function("api_detect_threat")
    async def detect_threat(
        request: Request,
        req: DetectionRequest,
        user: User = Depends(get_user),
    ):
        """
        Detect threats with full observability.
        """
        correlation_id = get_correlation_id()
        start_time = time.time()

        try:
            # Validate input
            validated_text = RequestValidator.validate_detect_request(req.text)

            # Create detection span
            with trace_detector(
                detector_name="enhanced_detector",
                input_text=validated_text,
            ) as span:
                # Detect threat
                result = await detector.async_detect(validated_text)

                # Update span with result
                span.set_attribute("result.is_threat", result["is_threat"])
                span.set_attribute("result.threat_type", result["threat_type"])
                span.set_attribute("result.confidence", result["confidence"])

                # Record metrics
                if enable_metrics:
                    duration = time.time() - start_time
                    metrics_collector.record_detection(
                        threat_type=result["threat_type"],
                        detection_method=result.get("detection_method", "unknown"),
                        duration=duration,
                        is_threat=result["is_threat"],
                    )

                    # Record fast/slow path
                    if "fast_path" in result.get("detection_method", ""):
                        metrics_collector.record_fast_path(
                            "threat" if result["is_threat"] else "safe"
                        )
                    else:
                        metrics_collector.record_slow_path()

                # Audit log threats
                if result["is_threat"] and audit_logger:
                    audit_logger.log_threat_detected(
                        user.username,
                        request.client.host if request.client else "unknown",
                        result["threat_type"],
                        result["confidence"],
                    )

                # Add correlation ID to response
                result["correlation_id"] = correlation_id

                return DetectionResponse(**result)

        except Exception as e:
            logger.error(f"Detection error: {e}", exc_info=True)
            if enable_metrics:
                metrics_collector.record_error(
                    error_type=type(e).__name__,
                    endpoint="/v1/detect",
                )
            raise

    @app.post("/v1/detect/batch", response_model=List[DetectionResponse])
    @trace_function("api_detect_batch")
    async def detect_batch(
        request: Request,
        req: dict,
        user: User = Depends(get_user),
    ):
        """Batch detection with observability."""
        correlation_id = get_correlation_id()
        texts = req.get("texts", [])

        # Validate batch
        RequestValidator.validate_batch_request(texts)

        # Process all
        import asyncio

        tasks = [detector.async_detect(text) for text in texts]
        results = await asyncio.gather(*tasks)

        # Add correlation IDs
        for result in results:
            result["correlation_id"] = correlation_id

        return [DetectionResponse(**r) for r in results]

    @app.get("/v1/health", response_model=HealthResponse)
    @trace_function("api_health_check")
    async def health_check(request: Request):
        """Health check with correlation ID."""
        return HealthResponse(
            status="healthy",
            version="2.0.0",
            correlation_id=get_correlation_id(),
        )

    @app.get("/metrics")
    async def get_metrics():
        """
        Prometheus metrics endpoint.

        Returns metrics in Prometheus text format.
        """
        if not enable_metrics:
            return {"error": "Metrics not enabled"}

        metrics_data = metrics_collector.get_metrics()
        return PlainTextResponse(
            content=metrics_data.decode("utf-8"),
            media_type="text/plain",
        )

    @app.get("/v1/metrics")
    @trace_function("api_get_metrics")
    async def get_detailed_metrics(user: User = Depends(get_user)):
        """Get detailed application metrics."""
        detector_metrics = detector.get_metrics()
        return {
            "correlation_id": get_correlation_id(),
            "detector": detector_metrics,
        }

    @app.on_event("shutdown")
    async def shutdown():
        """Cleanup on shutdown."""
        await detector.aclose()
        logger.info("✅ Application shutdown complete")

    logger.info("✅ Observable API initialized")
    return app


# Create app instance
app = create_observable_app(
    enable_tracing=True,
    enable_metrics=True,
    enable_security=True,
    otlp_endpoint=None,  # Set via env: OTEL_EXPORTER_OTLP_ENDPOINT
)
