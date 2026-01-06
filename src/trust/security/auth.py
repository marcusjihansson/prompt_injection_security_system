"""
Authentication system with API keys and JWT tokens.

Supports:
- API key authentication (for service-to-service)
- JWT token authentication (for user sessions)
- Role-based access control (admin, user, read-only)
"""

import hashlib
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


class User(BaseModel):
    """User model for authentication."""

    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: bool = False
    roles: List[str] = ["user"]


class TokenData(BaseModel):
    """JWT token payload."""

    username: Optional[str] = None
    roles: List[str] = []


class APIKeyAuth:
    """
    API Key authentication manager.

    Stores API keys in memory or Redis for production.
    """

    def __init__(self, use_redis: bool = False, redis_client=None):
        """
        Initialize API key auth.

        Args:
            use_redis: Whether to store keys in Redis
            redis_client: Optional Redis client
        """
        self.use_redis = use_redis
        self.redis_client = redis_client
        self.api_keys: Dict[str, User] = {}  # In-memory fallback

        # Load API keys from environment
        self._load_env_keys()

        logger.info(f"✅ APIKeyAuth initialized: {len(self.api_keys)} keys loaded")

    def _load_env_keys(self):
        """Load API keys from environment variables."""
        # Format: API_KEY_1=key:username:roles
        # Example: API_KEY_1=sk_abc123:admin_user:admin,user
        for key, value in os.environ.items():
            if key.startswith("API_KEY_"):
                try:
                    parts = value.split(":")
                    if len(parts) >= 2:
                        api_key = parts[0]
                        username = parts[1]
                        roles = parts[2].split(",") if len(parts) > 2 else ["user"]

                        self.api_keys[api_key] = User(
                            username=username,
                            roles=roles,
                        )
                        logger.info(f"Loaded API key for user: {username}")
                except Exception as e:
                    logger.warning(f"Failed to load API key {key}: {e}")

    def add_key(self, api_key: str, user: User):
        """
        Add an API key.

        Args:
            api_key: The API key string
            user: User associated with the key
        """
        if self.use_redis and self.redis_client:
            # Store in Redis
            import json

            self.redis_client.setex(
                f"api_key:{api_key}",
                86400 * 365,  # 1 year TTL
                json.dumps(user.dict()),
            )
        else:
            # Store in memory
            self.api_keys[api_key] = user

        logger.info(f"API key added for user: {user.username}")

    def verify_key(self, api_key: str) -> Optional[User]:
        """
        Verify an API key.

        Args:
            api_key: The API key to verify

        Returns:
            User if valid, None otherwise
        """
        if self.use_redis and self.redis_client:
            # Check Redis
            try:
                import json

                data = self.redis_client.get(f"api_key:{api_key}")
                if data:
                    return User(**json.loads(data))
            except Exception as e:
                logger.error(f"Redis key lookup failed: {e}")

        # Check in-memory
        return self.api_keys.get(api_key)

    def revoke_key(self, api_key: str):
        """
        Revoke an API key.

        Args:
            api_key: The API key to revoke
        """
        if self.use_redis and self.redis_client:
            self.redis_client.delete(f"api_key:{api_key}")

        self.api_keys.pop(api_key, None)
        logger.info(f"API key revoked: {api_key[:10]}...")

    @staticmethod
    def generate_key(prefix: str = "sk") -> str:
        """
        Generate a new API key.

        Args:
            prefix: Key prefix (e.g., "sk" for secret key)

        Returns:
            Generated API key
        """
        import secrets

        random_part = secrets.token_urlsafe(32)
        return f"{prefix}_{random_part}"


# Global API key auth instance
_api_key_auth: Optional[APIKeyAuth] = None


def get_api_key_auth() -> APIKeyAuth:
    """Get global API key auth instance."""
    global _api_key_auth
    if _api_key_auth is None:
        _api_key_auth = APIKeyAuth()
    return _api_key_auth


async def verify_api_key(api_key: str = Security(api_key_header)) -> User:
    """
    Verify API key from request header.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        User if valid

    Raises:
        HTTPException: If invalid or missing
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    auth = get_api_key_auth()
    user = auth.verify_key(api_key)

    if not user:
        logger.warning(f"Invalid API key attempted: {api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    logger.debug(f"API key authenticated: {user.username}")
    return user


class JWTAuth:
    """
    JWT token authentication manager.
    """

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token.

        Args:
            data: Data to encode in token
            expires_delta: Optional expiration time

        Returns:
            Encoded JWT token
        """
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> TokenData:
        """
        Verify and decode JWT token.

        Args:
            token: JWT token string

        Returns:
            TokenData with username and roles

        Raises:
            HTTPException: If invalid token
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            roles: List[str] = payload.get("roles", ["user"])

            if username is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: missing username",
                )

            return TokenData(username=username, roles=roles)

        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )


def create_access_token(username: str, roles: List[str] = None) -> str:
    """
    Convenience function to create access token.

    Args:
        username: Username
        roles: User roles

    Returns:
        JWT token string
    """
    if roles is None:
        roles = ["user"]

    data = {"sub": username, "roles": roles}
    return JWTAuth.create_access_token(data)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> User:
    """
    Get current user from JWT token.

    Args:
        credentials: Bearer token from Authorization header

    Returns:
        User object

    Raises:
        HTTPException: If invalid or missing token
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = JWTAuth.verify_token(credentials.credentials)

    # In production, you'd look up the user from a database
    # For now, create a user from token data
    user = User(
        username=token_data.username,
        roles=token_data.roles,
    )

    logger.debug(f"JWT authenticated: {user.username}")
    return user


def require_roles(required_roles: List[str]):
    """
    Dependency to require specific roles.

    Usage:
        @app.get("/admin")
        async def admin_endpoint(user: User = Depends(require_roles(["admin"]))):
            ...

    Args:
        required_roles: List of required roles

    Returns:
        Dependency function
    """

    async def check_roles(user: User = Depends(get_current_user)) -> User:
        if not any(role in user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}",
            )
        return user

    return check_roles


# Combined authentication (API key OR JWT)
async def verify_authentication(
    api_key: Optional[str] = Security(api_key_header),
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> User:
    """
    Verify authentication using either API key or JWT token.

    Args:
        api_key: Optional API key from header
        credentials: Optional Bearer token from header

    Returns:
        Authenticated User

    Raises:
        HTTPException: If neither auth method succeeds
    """
    # Try API key first
    if api_key:
        try:
            return await verify_api_key(api_key)
        except HTTPException:
            pass  # Try JWT next

    # Try JWT token
    if credentials:
        try:
            return await get_current_user(credentials)
        except HTTPException:
            pass

    # Neither worked
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key or Authorization Bearer token",
        headers={"WWW-Authenticate": "Bearer, ApiKey"},
    )
