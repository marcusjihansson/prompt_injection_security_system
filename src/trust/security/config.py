"""
Security configuration from environment variables.
"""

import os
from typing import List


def get_jwt_config() -> dict:
    """Get JWT configuration."""
    return {
        "secret_key": os.getenv("JWT_SECRET_KEY", "your-secret-key-change-this-in-production"),
        "algorithm": "HS256",
        "expire_minutes": int(os.getenv("JWT_EXPIRE_MINUTES", "30")),
    }


def get_rate_limit_config() -> dict:
    """Get rate limiting configuration."""
    return {
        "default_limit": os.getenv("RATE_LIMIT_DEFAULT", "100/minute"),
        "detect_limit": os.getenv("RATE_LIMIT_DETECT", "60/minute"),
        "batch_limit": os.getenv("RATE_LIMIT_BATCH", "10/minute"),
        "use_redis": os.getenv("RATE_LIMIT_USE_REDIS", "true").lower() == "true",
    }


def get_audit_config() -> dict:
    """Get audit logging configuration."""
    return {
        "log_file": os.getenv("AUDIT_LOG_FILE", "audit.log"),
        "use_structlog": os.getenv("AUDIT_USE_STRUCTLOG", "true").lower() == "true",
        "include_request_data": os.getenv("AUDIT_INCLUDE_REQUEST_DATA", "false").lower() == "true",
    }


def get_security_headers_config() -> dict:
    """Get security headers configuration."""
    return {
        "enable_hsts": os.getenv("SECURITY_ENABLE_HSTS", "true").lower() == "true",
        "hsts_max_age": int(os.getenv("SECURITY_HSTS_MAX_AGE", "31536000")),
        "enable_csp": os.getenv("SECURITY_ENABLE_CSP", "true").lower() == "true",
        "csp_directives": os.getenv("SECURITY_CSP_DIRECTIVES", "default-src 'self'"),
    }


def get_cors_config() -> dict:
    """Get CORS configuration."""
    origins_str = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000")
    origins = [o.strip() for o in origins_str.split(",") if o.strip()]

    return {
        "allowed_origins": origins,
        "allow_credentials": True,
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["*"],
    }


def get_input_validation_config() -> dict:
    """Get input validation configuration."""
    return {
        "max_length": int(os.getenv("INPUT_MAX_LENGTH", "10000")),
        "max_batch_size": int(os.getenv("INPUT_MAX_BATCH_SIZE", "100")),
        "allow_html": os.getenv("INPUT_ALLOW_HTML", "false").lower() == "true",
    }


def get_api_security_config() -> dict:
    """Get API security configuration."""
    return {
        "enable_auth": os.getenv("API_ENABLE_AUTH", "true").lower() == "true",
        "enable_rate_limit": os.getenv("API_ENABLE_RATE_LIMIT", "true").lower() == "true",
        "enable_audit_log": os.getenv("API_ENABLE_AUDIT_LOG", "true").lower() == "true",
    }
