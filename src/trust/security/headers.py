"""
Security headers middleware for FastAPI.

Adds security headers to all responses to protect against common attacks.
"""

import logging
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security: HSTS
    - Content-Security-Policy: CSP
    - Referrer-Policy: no-referrer
    """

    def __init__(
        self,
        app,
        enable_hsts: bool = True,
        hsts_max_age: int = 31536000,
        enable_csp: bool = True,
        csp_directives: str = "default-src 'self'",
    ):
        """
        Initialize security headers middleware.

        Args:
            app: FastAPI application
            enable_hsts: Enable HTTP Strict Transport Security
            hsts_max_age: HSTS max age in seconds (default: 1 year)
            enable_csp: Enable Content Security Policy
            csp_directives: CSP directives string
        """
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.hsts_max_age = hsts_max_age
        self.enable_csp = enable_csp
        self.csp_directives = csp_directives
        logger.info("✅ SecurityHeadersMiddleware initialized")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Add security headers to response.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response with security headers
        """
        response = await call_next(request)

        # X-Content-Type-Options: Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options: Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # X-XSS-Protection: Enable XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy: Control referrer information
        response.headers["Referrer-Policy"] = "no-referrer"

        # Strict-Transport-Security: Force HTTPS
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={self.hsts_max_age}; includeSubDomains; preload"
            )

        # Content-Security-Policy: Restrict resource loading
        if self.enable_csp:
            response.headers["Content-Security-Policy"] = self.csp_directives

        # Permissions-Policy: Control browser features
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


def configure_cors(app, allowed_origins: list = None):
    """
    Configure CORS (Cross-Origin Resource Sharing) for the application.

    Args:
        app: FastAPI application
        allowed_origins: List of allowed origins (default: localhost only)
    """
    from fastapi.middleware.cors import CORSMiddleware

    if allowed_origins is None:
        allowed_origins = [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:8000",
        ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        max_age=3600,
    )

    logger.info(f"✅ CORS configured: {len(allowed_origins)} origins allowed")
