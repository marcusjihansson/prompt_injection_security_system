"""
Security components for production deployment.

Includes:
- Rate limiting
- API authentication (API keys and JWT)
- Audit logging
- Input validation
- Security headers
"""

from trust.security.audit import AuditLogger, SecurityEvent
from trust.security.auth import (
    APIKeyAuth,
    JWTAuth,
    create_access_token,
    get_current_user,
    verify_api_key,
)
from trust.security.headers import SecurityHeadersMiddleware
from trust.security.rate_limit import RateLimiter, rate_limit
from trust.security.validation import InputValidator, sanitize_input

__all__ = [
    # Authentication
    "APIKeyAuth",
    "JWTAuth",
    "create_access_token",
    "get_current_user",
    "verify_api_key",
    # Audit logging
    "AuditLogger",
    "SecurityEvent",
    # Rate limiting
    "RateLimiter",
    "rate_limit",
    # Security headers
    "SecurityHeadersMiddleware",
    # Input validation
    "InputValidator",
    "sanitize_input",
]
