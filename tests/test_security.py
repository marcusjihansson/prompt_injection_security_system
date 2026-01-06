"""
Tests for security features:
- Rate limiting
- Authentication (API keys and JWT)
- Audit logging
- Input validation
- Security headers
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from trust.security.audit import AuditLogger, SecurityEvent
from trust.security.auth import APIKeyAuth, JWTAuth, User, create_access_token
from trust.security.rate_limit import IPRateLimiter
from trust.security.validation import InputValidator, sanitize_input


class TestAPIKeyAuth:
    """Test API key authentication."""

    def test_api_key_auth_initialization(self):
        """Test API key auth can be initialized."""
        auth = APIKeyAuth()
        assert auth is not None
        assert isinstance(auth.api_keys, dict)

    def test_generate_api_key(self):
        """Test API key generation."""
        key = APIKeyAuth.generate_key(prefix="sk")
        assert key.startswith("sk_")
        assert len(key) > 10

    def test_add_and_verify_key(self):
        """Test adding and verifying API keys."""
        auth = APIKeyAuth()
        user = User(username="testuser", roles=["user"])
        api_key = "test_key_123"

        # Add key
        auth.add_key(api_key, user)

        # Verify key
        verified_user = auth.verify_key(api_key)
        assert verified_user is not None
        assert verified_user.username == "testuser"

    def test_verify_invalid_key(self):
        """Test verifying invalid API key."""
        auth = APIKeyAuth()
        result = auth.verify_key("invalid_key")
        assert result is None

    def test_revoke_key(self):
        """Test revoking API key."""
        auth = APIKeyAuth()
        user = User(username="testuser", roles=["user"])
        api_key = "test_key_123"

        auth.add_key(api_key, user)
        assert auth.verify_key(api_key) is not None

        auth.revoke_key(api_key)
        assert auth.verify_key(api_key) is None


class TestJWTAuth:
    """Test JWT authentication."""

    def test_create_access_token(self):
        """Test creating JWT access token."""
        token = create_access_token(username="testuser", roles=["user"])
        assert isinstance(token, str)
        assert len(token) > 20

    def test_verify_valid_token(self):
        """Test verifying valid JWT token."""
        token = create_access_token(username="testuser", roles=["user", "admin"])
        token_data = JWTAuth.verify_token(token)

        assert token_data.username == "testuser"
        assert "user" in token_data.roles
        assert "admin" in token_data.roles

    def test_verify_invalid_token(self):
        """Test verifying invalid JWT token."""
        with pytest.raises(HTTPException) as exc_info:
            JWTAuth.verify_token("invalid_token")
        assert exc_info.value.status_code == 401


class TestRateLimiting:
    """Test rate limiting."""

    def test_ip_rate_limiter_initialization(self):
        """Test IP rate limiter initialization."""
        limiter = IPRateLimiter(requests_per_minute=10)
        assert limiter is not None
        assert limiter.requests_per_minute == 10

    def test_rate_limiter_allows_requests(self):
        """Test rate limiter allows requests within limit."""
        limiter = IPRateLimiter(requests_per_minute=5)

        # First 5 requests should be allowed
        for i in range(5):
            assert limiter.is_allowed("192.168.1.1") is True

    def test_rate_limiter_blocks_excess(self):
        """Test rate limiter blocks excess requests."""
        limiter = IPRateLimiter(requests_per_minute=5)

        # First 5 allowed
        for i in range(5):
            limiter.is_allowed("192.168.1.1")

        # 6th should be blocked
        assert limiter.is_allowed("192.168.1.1") is False

    def test_rate_limiter_per_ip(self):
        """Test rate limiter works per IP."""
        limiter = IPRateLimiter(requests_per_minute=2)

        # Use up limit for IP1
        limiter.is_allowed("192.168.1.1")
        limiter.is_allowed("192.168.1.1")

        # IP1 should be blocked
        assert limiter.is_allowed("192.168.1.1") is False

        # But IP2 should still work
        assert limiter.is_allowed("192.168.1.2") is True

    def test_rate_limiter_reset(self):
        """Test rate limiter reset."""
        limiter = IPRateLimiter(requests_per_minute=2)

        # Use up limit
        limiter.is_allowed("192.168.1.1")
        limiter.is_allowed("192.168.1.1")
        assert limiter.is_allowed("192.168.1.1") is False

        # Reset
        limiter.reset("192.168.1.1")

        # Should work again
        assert limiter.is_allowed("192.168.1.1") is True


class TestAuditLogging:
    """Test audit logging."""

    def test_audit_logger_initialization(self):
        """Test audit logger initialization."""
        logger = AuditLogger(log_file=None, use_structlog=False)
        assert logger is not None

    def test_log_event(self):
        """Test logging security events."""
        logger = AuditLogger(log_file=None, use_structlog=False)

        # Should not raise
        logger.log_event(
            SecurityEvent.AUTH_SUCCESS,
            user="testuser",
            ip_address="192.168.1.1",
            details={"method": "api_key"},
        )

    def test_log_auth_success(self):
        """Test logging auth success."""
        logger = AuditLogger(log_file=None, use_structlog=False)
        logger.log_auth_success("testuser", "192.168.1.1", "api_key")

    def test_log_auth_failure(self):
        """Test logging auth failure."""
        logger = AuditLogger(log_file=None, use_structlog=False)
        logger.log_auth_failure("baduser", "192.168.1.1", "invalid_key")

    def test_log_threat_detected(self):
        """Test logging threat detection."""
        logger = AuditLogger(log_file=None, use_structlog=False)
        logger.log_threat_detected(
            "testuser",
            "192.168.1.1",
            "prompt_injection",
            0.95,
            "test input",
        )

    def test_log_rate_limit_exceeded(self):
        """Test logging rate limit exceeded."""
        logger = AuditLogger(log_file=None, use_structlog=False)
        logger.log_rate_limit_exceeded("192.168.1.1", "100/minute")


class TestInputValidation:
    """Test input validation."""

    def test_input_validator_initialization(self):
        """Test input validator initialization."""
        validator = InputValidator(max_length=1000)
        assert validator is not None
        assert validator.max_length == 1000

    def test_validate_valid_input(self):
        """Test validating valid input."""
        validator = InputValidator(max_length=1000)
        result = validator.validate("Hello, world!", field_name="text")
        assert result == "Hello, world!"

    def test_validate_exceeds_max_length(self):
        """Test input exceeding max length."""
        validator = InputValidator(max_length=10)
        with pytest.raises(HTTPException) as exc_info:
            validator.validate("This is too long for the limit", field_name="text")
        assert exc_info.value.status_code == 400

    def test_validate_empty_input(self):
        """Test empty input validation."""
        validator = InputValidator()
        with pytest.raises(HTTPException) as exc_info:
            validator.validate("", field_name="text")
        assert exc_info.value.status_code == 400

    def test_validate_none_input(self):
        """Test None input validation."""
        validator = InputValidator()
        with pytest.raises(HTTPException) as exc_info:
            validator.validate(None, field_name="text")
        assert exc_info.value.status_code == 400

    def test_detect_dangerous_patterns(self):
        """Test detecting dangerous patterns."""
        validator = InputValidator()

        # Script tag
        with pytest.raises(HTTPException):
            validator.validate("<script>alert('xss')</script>", field_name="text")

        # JavaScript protocol
        with pytest.raises(HTTPException):
            validator.validate("javascript:alert('xss')", field_name="text")

        # Event handler
        with pytest.raises(HTTPException):
            validator.validate("<img onerror='alert(1)'>", field_name="text")

    def test_sanitize_html(self):
        """Test HTML sanitization."""
        validator = InputValidator(allow_html=False)
        result = validator.validate("<b>bold</b>", field_name="text")
        assert "&lt;b&gt;" in result  # HTML escaped

    def test_sanitize_input_function(self):
        """Test convenience sanitize function."""
        result = sanitize_input("Hello, world!", max_length=1000)
        assert result == "Hello, world!"

    def test_validate_length(self):
        """Test length validation."""
        validator = InputValidator(max_length=1000)

        # Valid
        assert validator.validate_length("test", min_length=1, max_length=10) is True

        # Too short
        with pytest.raises(HTTPException):
            validator.validate_length("", min_length=1)

        # Too long
        with pytest.raises(HTTPException):
            validator.validate_length("x" * 20, min_length=1, max_length=10)


class TestSecureAPI:
    """Test secure API endpoints."""

    def test_secure_api_initialization(self):
        """Test secure API can be initialized."""
        from trust.api.secure_api import create_secure_app

        app = create_secure_app(
            enable_rate_limiting=False,
            enable_authentication=False,
            enable_audit_logging=False,
            enable_valkey=False,
        )
        assert app is not None

    def test_health_endpoint(self):
        """Test health check endpoint."""
        from trust.api.secure_api import create_secure_app

        app = create_secure_app(
            enable_rate_limiting=False,
            enable_authentication=False,
            enable_valkey=False,
        )
        client = TestClient(app)

        response = client.get("/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_detect_endpoint_without_auth(self):
        """Test detect endpoint without authentication."""
        from trust.api.secure_api import create_secure_app

        app = create_secure_app(
            enable_rate_limiting=False,
            enable_authentication=False,
            enable_valkey=False,
        )
        client = TestClient(app)

        response = client.post("/v1/detect", json={"text": "Hello, world!"})
        assert response.status_code == 200
        assert "is_threat" in response.json()

    def test_detect_endpoint_with_invalid_input(self):
        """Test detect endpoint with invalid input."""
        from trust.api.secure_api import create_secure_app

        app = create_secure_app(
            enable_rate_limiting=False,
            enable_authentication=False,
            enable_valkey=False,
        )
        client = TestClient(app)

        # Empty input
        response = client.post("/v1/detect", json={"text": ""})
        assert response.status_code == 400

    def test_batch_endpoint(self):
        """Test batch detection endpoint."""
        from trust.api.secure_api import create_secure_app

        app = create_secure_app(
            enable_rate_limiting=False,
            enable_authentication=False,
            enable_valkey=False,
        )
        client = TestClient(app)

        response = client.post(
            "/v1/detect/batch",
            json={"texts": ["Hello", "World"]},
        )
        assert response.status_code == 200
        assert len(response.json()) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
