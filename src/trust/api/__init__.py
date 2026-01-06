"""
FastAPI application for threat detection service.
"""

from trust.api.api import create_app
from trust.api.app import create_fastapi_app

__all__ = [
    "create_fastapi_app",
    "create_app",
]
