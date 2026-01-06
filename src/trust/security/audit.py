"""
Audit logging for security events.

Tracks:
- Authentication attempts
- Threat detections
- API access
- Rate limit violations
- Security policy violations
"""

import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

import structlog

logger = logging.getLogger(__name__)


class SecurityEvent(str, Enum):
    """Security event types for audit logging."""

    # Authentication
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    TOKEN_CREATED = "token_created"
    TOKEN_EXPIRED = "token_expired"

    # Threat Detection
    THREAT_DETECTED = "threat_detected"
    THREAT_BLOCKED = "threat_blocked"
    SAFE_REQUEST = "safe_request"

    # Rate Limiting
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    RATE_LIMIT_WARNING = "rate_limit_warning"

    # Access Control
    ACCESS_DENIED = "access_denied"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"

    # System Events
    SYSTEM_ERROR = "system_error"
    CONFIG_CHANGED = "config_changed"
    CACHE_CLEARED = "cache_cleared"


class AuditLogger:
    """
    Audit logger for security events.

    Logs events in structured format for compliance and forensics.
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        use_structlog: bool = True,
        include_request_data: bool = False,
    ):
        """
        Initialize audit logger.

        Args:
            log_file: Optional file path for audit logs
            use_structlog: Whether to use structured logging
            include_request_data: Whether to log full request data (sensitive!)
        """
        self.log_file = log_file
        self.use_structlog = use_structlog
        self.include_request_data = include_request_data

        # Initialize structured logger if enabled
        if use_structlog:
            structlog.configure(
                processors=[
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.add_log_level,
                    structlog.processors.JSONRenderer(),
                ],
            )
            self.struct_logger = structlog.get_logger("audit")
        else:
            self.struct_logger = None

        # File handler for audit logs
        if log_file:
            self._setup_file_handler()

        logger.info(f"✅ AuditLogger initialized: file={log_file or 'none'}")

    def _setup_file_handler(self):
        """Set up file handler for audit logs."""
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)

        audit_logger = logging.getLogger("audit")
        audit_logger.addHandler(file_handler)
        audit_logger.setLevel(logging.INFO)

    def log_event(
        self,
        event_type: SecurityEvent,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ):
        """
        Log a security event.

        Args:
            event_type: Type of security event
            user: Username or identifier
            ip_address: Client IP address
            details: Additional event details
            severity: Log severity (info, warning, error)
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "user": user or "anonymous",
            "ip_address": ip_address or "unknown",
            "severity": severity,
        }

        if details:
            event["details"] = details

        # Log with structured logger if available
        if self.struct_logger:
            log_func = getattr(self.struct_logger, severity, self.struct_logger.info)
            log_func("security_event", **event)
        else:
            # Standard logging
            log_msg = json.dumps(event)
            log_func = getattr(logger, severity, logger.info)
            log_func(log_msg)

        # Also log to dedicated audit logger if file handler exists
        if self.log_file:
            audit_logger = logging.getLogger("audit")
            audit_logger.info(json.dumps(event))

    def log_auth_success(self, user: str, ip_address: str, method: str = "api_key"):
        """Log successful authentication."""
        self.log_event(
            SecurityEvent.AUTH_SUCCESS,
            user=user,
            ip_address=ip_address,
            details={"method": method},
            severity="info",
        )

    def log_auth_failure(self, user: Optional[str], ip_address: str, reason: str):
        """Log failed authentication attempt."""
        self.log_event(
            SecurityEvent.AUTH_FAILURE,
            user=user,
            ip_address=ip_address,
            details={"reason": reason},
            severity="warning",
        )

    def log_threat_detected(
        self,
        user: str,
        ip_address: str,
        threat_type: str,
        confidence: float,
        input_text: Optional[str] = None,
    ):
        """Log threat detection."""
        details = {
            "threat_type": threat_type,
            "confidence": confidence,
        }

        if self.include_request_data and input_text:
            # Truncate for security
            details["input_preview"] = input_text[:100]

        self.log_event(
            SecurityEvent.THREAT_DETECTED,
            user=user,
            ip_address=ip_address,
            details=details,
            severity="warning",
        )

    def log_threat_blocked(
        self,
        user: str,
        ip_address: str,
        threat_type: str,
        confidence: float,
    ):
        """Log blocked threat."""
        self.log_event(
            SecurityEvent.THREAT_BLOCKED,
            user=user,
            ip_address=ip_address,
            details={
                "threat_type": threat_type,
                "confidence": confidence,
            },
            severity="warning",
        )

    def log_rate_limit_exceeded(self, ip_address: str, limit: str):
        """Log rate limit violation."""
        self.log_event(
            SecurityEvent.RATE_LIMIT_EXCEEDED,
            ip_address=ip_address,
            details={"limit": limit},
            severity="warning",
        )

    def log_access_denied(
        self,
        user: str,
        ip_address: str,
        resource: str,
        reason: str,
    ):
        """Log access denial."""
        self.log_event(
            SecurityEvent.ACCESS_DENIED,
            user=user,
            ip_address=ip_address,
            details={
                "resource": resource,
                "reason": reason,
            },
            severity="warning",
        )

    def log_system_error(
        self,
        error_type: str,
        error_message: str,
        user: Optional[str] = None,
    ):
        """Log system error."""
        self.log_event(
            SecurityEvent.SYSTEM_ERROR,
            user=user,
            details={
                "error_type": error_type,
                "error_message": error_message,
            },
            severity="error",
        )


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(
            log_file="audit.log",
            use_structlog=True,
        )
    return _audit_logger


def init_audit_logger(
    log_file: Optional[str] = "audit.log",
    use_structlog: bool = True,
) -> AuditLogger:
    """
    Initialize global audit logger.

    Args:
        log_file: Path to audit log file
        use_structlog: Whether to use structured logging

    Returns:
        AuditLogger instance
    """
    global _audit_logger
    _audit_logger = AuditLogger(
        log_file=log_file,
        use_structlog=use_structlog,
    )
    return _audit_logger


# Convenience functions
def audit_auth_success(user: str, ip_address: str, method: str = "api_key"):
    """Convenience function to log auth success."""
    get_audit_logger().log_auth_success(user, ip_address, method)


def audit_auth_failure(user: Optional[str], ip_address: str, reason: str):
    """Convenience function to log auth failure."""
    get_audit_logger().log_auth_failure(user, ip_address, reason)


def audit_threat_detected(
    user: str,
    ip_address: str,
    threat_type: str,
    confidence: float,
    input_text: Optional[str] = None,
):
    """Convenience function to log threat detection."""
    get_audit_logger().log_threat_detected(user, ip_address, threat_type, confidence, input_text)


def audit_rate_limit_exceeded(ip_address: str, limit: str):
    """Convenience function to log rate limit exceeded."""
    get_audit_logger().log_rate_limit_exceeded(ip_address, limit)
