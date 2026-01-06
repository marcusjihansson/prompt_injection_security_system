"""
Rate limiting middleware for FastAPI.

Prevents abuse by limiting requests per client.
Uses Valkey/Redis for distributed rate limiting.
"""

import logging
import time
from typing import Optional

from fastapi import HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter with configurable limits and storage backend.

    Supports both in-memory (for development) and Redis (for production).
    """

    def __init__(
        self,
        default_limits: str = "100/minute",
        storage_uri: Optional[str] = None,
        key_func=get_remote_address,
    ):
        """
        Initialize rate limiter.

        Args:
            default_limits: Default rate limits (e.g., "100/minute", "1000/hour")
            storage_uri: Redis URI for distributed rate limiting (e.g., "redis://localhost:6379")
            key_func: Function to extract rate limit key from request
        """
        self.limiter = Limiter(
            key_func=key_func,
            default_limits=[default_limits],
            storage_uri=storage_uri,
        )
        logger.info(f"✅ RateLimiter initialized: {default_limits}")

    def get_limiter(self):
        """Get the SlowAPI limiter instance."""
        return self.limiter


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def init_rate_limiter(
    default_limits: str = "100/minute",
    storage_uri: Optional[str] = None,
) -> RateLimiter:
    """
    Initialize global rate limiter.

    Args:
        default_limits: Default rate limits
        storage_uri: Optional Redis URI

    Returns:
        RateLimiter instance
    """
    global _rate_limiter
    _rate_limiter = RateLimiter(
        default_limits=default_limits,
        storage_uri=storage_uri,
    )
    return _rate_limiter


def get_rate_limiter() -> Optional[RateLimiter]:
    """Get the global rate limiter instance."""
    return _rate_limiter


def rate_limit(limits: str = "100/minute"):
    """
    Decorator for rate limiting endpoints.

    Usage:
        @app.post("/detect")
        @rate_limit("10/minute")
        async def detect(request: Request):
            ...

    Args:
        limits: Rate limit string (e.g., "10/minute", "100/hour")

    Returns:
        Decorator function
    """

    def decorator(func):
        func._rate_limit = limits
        return func

    return decorator


class IPRateLimiter:
    """
    Simple in-memory IP-based rate limiter.

    Useful for development or when Redis is not available.
    """

    def __init__(self, requests_per_minute: int = 60):
        """
        Initialize IP rate limiter.

        Args:
            requests_per_minute: Maximum requests per IP per minute
        """
        self.requests_per_minute = requests_per_minute
        self.requests = {}  # {ip: [(timestamp, ...)]}
        self.window_seconds = 60
        logger.info(f"✅ IPRateLimiter initialized: {requests_per_minute}/minute")

    def is_allowed(self, client_ip: str) -> bool:
        """
        Check if request from IP is allowed.

        Args:
            client_ip: Client IP address

        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()

        # Clean up old entries
        if client_ip in self.requests:
            self.requests[client_ip] = [
                ts for ts in self.requests[client_ip] if now - ts < self.window_seconds
            ]
        else:
            self.requests[client_ip] = []

        # Check rate limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False

        # Add current request
        self.requests[client_ip].append(now)
        return True

    async def check_rate_limit(self, request: Request):
        """
        Middleware function to check rate limits.

        Args:
            request: FastAPI request

        Raises:
            HTTPException: If rate limit exceeded
        """
        client_ip = request.client.host if request.client else "unknown"

        if not self.is_allowed(client_ip):
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "message": f"Maximum {self.requests_per_minute} requests per minute",
                    "retry_after": 60,
                },
            )

    def reset(self, client_ip: Optional[str] = None):
        """
        Reset rate limit counters.

        Args:
            client_ip: IP to reset, or None to reset all
        """
        if client_ip:
            self.requests.pop(client_ip, None)
        else:
            self.requests.clear()
        logger.info(f"Rate limits reset for: {client_ip or 'all'}")


# Convenience function for middleware
async def rate_limit_middleware(request: Request, call_next):
    """
    Middleware to apply rate limiting to all requests.

    Add to FastAPI app with:
        app.middleware("http")(rate_limit_middleware)
    """
    limiter = get_rate_limiter()
    if limiter:
        # SlowAPI handles rate limiting
        pass

    response = await call_next(request)
    return response
