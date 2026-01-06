"""
Secure FastAPI application with all security features enabled.

Features:
- Rate limiting
- API key and JWT authentication
- Audit logging
- Input validation
- Security headers
- CORS configuration
- API versioning
"""

import logging
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from trust.production import EnhancedProductionThreatDetector
from trust.security.audit import SecurityEvent, get_audit_logger
from trust.security.auth import User, create_access_token, require_roles, verify_authentication
from trust.security.headers import SecurityHeadersMiddleware, configure_cors
from trust.security.rate_limit import get_rate_limiter, init_rate_limiter
from trust.security.validation import RequestValidator, sanitize_input

logger = logging.getLogger(__name__)


# Request/Response Models
class DetectionRequest(BaseModel):
    """Request model for single threat detection."""

    text: str


class BatchDetectionRequest(BaseModel):
    """Request model for batch threat detection."""

    texts: List[str]


class DetectionResponse(BaseModel):
    """Response model for threat detection."""

    is_threat: bool
    threat_type: str
    confidence: float
    reasoning: str
    detection_method: Optional[str] = None
    latency_ms: Optional[float] = None


class LoginRequest(BaseModel):
    """Request model for login."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Response model for authentication token."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    version: str
    metrics: dict


class ErrorResponse(BaseModel):
    """Response model for errors."""

    error: str
    message: str
    status_code: int


def create_secure_app(
    enable_rate_limiting: bool = True,
    enable_authentication: bool = True,
    enable_audit_logging: bool = True,
    enable_valkey: bool = True,
) -> FastAPI:
    """
    Create secure FastAPI application with all security features.

    Args:
        enable_rate_limiting: Enable rate limiting
        enable_authentication: Require authentication
        enable_audit_logging: Enable audit logging
        enable_valkey: Enable Valkey/Redis for caching and rate limiting

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Secure Threat Detection API",
        version="2.0.0",
        description="Production-ready threat detection with security features",
        docs_url="/docs" if not enable_authentication else None,  # Disable in production
        redoc_url="/redoc" if not enable_authentication else None,
    )

    # Initialize detector
    detector = EnhancedProductionThreatDetector(
        enable_regex_baseline=True,
        enable_adaptive=True,
        enable_valkey=enable_valkey,
        enable_connection_pool=True,
    )

    # Initialize rate limiter
    rate_limiter = None
    if enable_rate_limiting:
        storage_uri = "redis://localhost:6379" if enable_valkey else None
        rate_limiter = init_rate_limiter(
            default_limits="100/minute",
            storage_uri=storage_uri,
        )
        app.state.limiter = rate_limiter.get_limiter()
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Initialize audit logger
    audit_logger = None
    if enable_audit_logging:
        audit_logger = get_audit_logger()

    # Add security headers middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # Configure CORS
    configure_cors(app, allowed_origins=["http://localhost:3000"])

    # Helper functions
    def get_client_ip(request: Request) -> str:
        """Extract client IP from request."""
        return request.client.host if request.client else "unknown"

    def audit_request(
        request: Request,
        user: User,
        event: SecurityEvent,
        details: dict = None,
    ):
        """Audit log a request."""
        if audit_logger:
            audit_logger.log_event(
                event,
                user=user.username,
                ip_address=get_client_ip(request),
                details=details,
            )

    # Authentication dependency
    async def get_authenticated_user(request: Request) -> User:
        """Get authenticated user or raise 401."""
        if not enable_authentication:
            # Return anonymous user if auth disabled
            return User(username="anonymous", roles=["user"])

        user = await verify_authentication()

        # Audit successful auth
        if audit_logger:
            audit_logger.log_auth_success(
                user.username,
                get_client_ip(request),
                method="api_key_or_jwt",
            )

        return user

    # Routes
    @app.post("/v1/detect", response_model=DetectionResponse)
    async def detect_threat(
        request: Request,
        req: DetectionRequest,
        user: User = Depends(get_authenticated_user),
    ):
        """
        Detect threats in single text input.

        Requires authentication. Rate limited.
        """
        try:
            # Validate input
            validated_text = RequestValidator.validate_detect_request(req.text)

            # Detect threat
            result = await detector.async_detect(validated_text)

            # Audit log
            if result["is_threat"]:
                audit_request(
                    request,
                    user,
                    SecurityEvent.THREAT_DETECTED,
                    details={
                        "threat_type": result["threat_type"],
                        "confidence": result["confidence"],
                    },
                )

            return DetectionResponse(**result)

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Detection error: {e}")
            if audit_logger:
                audit_logger.log_system_error(
                    error_type="detection_error",
                    error_message=str(e),
                    user=user.username,
                )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during detection",
            )

    @app.post("/v1/detect/batch", response_model=List[DetectionResponse])
    async def detect_threats_batch(
        request: Request,
        req: BatchDetectionRequest,
        user: User = Depends(get_authenticated_user),
    ):
        """
        Batch threat detection.

        Requires authentication. Rate limited.
        """
        try:
            # Validate batch
            RequestValidator.validate_batch_request(req.texts, max_batch_size=100)

            # Process all texts
            import asyncio

            tasks = [detector.async_detect(text) for text in req.texts]
            results = await asyncio.gather(*tasks)

            # Audit threats
            threats_found = sum(1 for r in results if r["is_threat"])
            if threats_found > 0:
                audit_request(
                    request,
                    user,
                    SecurityEvent.THREAT_DETECTED,
                    details={
                        "batch_size": len(req.texts),
                        "threats_found": threats_found,
                    },
                )

            return [DetectionResponse(**r) for r in results]

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Batch detection error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during batch detection",
            )

    @app.get("/v1/health", response_model=HealthResponse)
    async def health_check():
        """
        Health check endpoint (no authentication required).
        """
        metrics = detector.get_metrics()
        return HealthResponse(
            status="healthy",
            version="2.0.0",
            metrics=metrics,
        )

    @app.get("/v1/metrics")
    async def get_metrics(
        request: Request,
        user: User = Depends(require_roles(["admin"])),
    ):
        """
        Get detailed metrics (admin only).
        """
        return detector.get_metrics()

    @app.post("/v1/auth/token", response_model=TokenResponse)
    async def login(request: Request, login_req: LoginRequest):
        """
        Login to get JWT token (for testing).

        In production, integrate with your user database.
        """
        # Simple hardcoded check for demo
        # In production: verify against database with hashed passwords
        if login_req.username == "demo" and login_req.password == "demo":
            token = create_access_token(
                username=login_req.username,
                roles=["user"],
            )

            if audit_logger:
                audit_logger.log_auth_success(
                    login_req.username,
                    get_client_ip(request),
                    method="jwt",
                )

            return TokenResponse(
                access_token=token,
                token_type="bearer",
                expires_in=1800,
            )
        else:
            if audit_logger:
                audit_logger.log_auth_failure(
                    login_req.username,
                    get_client_ip(request),
                    reason="invalid_credentials",
                )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

    # Error handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions with consistent format."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": exc.detail,
                "status_code": exc.status_code,
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)

        if audit_logger:
            audit_logger.log_system_error(
                error_type="unhandled_exception",
                error_message=str(exc),
            )

        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message": "An unexpected error occurred",
                "status_code": 500,
            },
        )

    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown."""
        await detector.aclose()
        logger.info("✅ Application shutdown complete")

    logger.info("✅ Secure API initialized")
    return app


# Create app instance
app = create_secure_app(
    enable_rate_limiting=True,
    enable_authentication=True,
    enable_audit_logging=True,
    enable_valkey=True,
)
