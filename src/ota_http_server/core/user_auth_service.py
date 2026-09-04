# core/user_auth_service.py
"""Authentication service for human/API users of the REST API.

This is intentionally kept separate from :class:`ota_http_server.core.auth_service.AuthService`,
which authenticates OTA devices for firmware downloads. REST API user tokens and
device tokens use different audiences so a token issued for one purpose cannot be
replayed against the other subsystem.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict
from uuid import uuid4

import jwt
from flask import abort

from .data_models import TokenResult, User
from .passwords import Passwords
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

# Small allowance for clock skew between the issuer and this server when
# validating the "iat" (issued-at) claim.
IAT_LEEWAY_SECONDS = 5


class UserAuthService:
    """Authenticates REST API users and issues/validates their JWT access tokens."""

    def __init__(
        self,
        jwt_secret: str,
        jwt_algorithm: str,
        jwt_issuer: str,
        jwt_audience: str,
        jwt_expiry: int,
    ):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_issuer = jwt_issuer
        self.jwt_audience = jwt_audience
        self.jwt_expiry = jwt_expiry

    def authenticate(self, username: str, password: str, db_service) -> User | None:
        """Verify username/password and return the active user, or None on any failure.

        The same generic failure (None) is returned whether the username does not
        exist, the password is wrong, or the user is inactive, so callers cannot
        distinguish these cases and leak information about account existence.
        """
        user = db_service.user_get_by_username(username)
        if user is None:
            return None
        if not Passwords.verify(password, user.password_hash):
            return None
        if not user.is_active:
            return None
        return user

    def create_access_token(self, user: User) -> TokenResult:
        """Create a JWT access token carrying only identity/authorization claims."""
        now = datetime.now(UTC)
        now_ts = int(now.timestamp())

        payload: Dict[str, Any] = {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
            "iat": now_ts,
            "exp": now_ts + self.jwt_expiry,
            "iss": self.jwt_issuer,
            "aud": self.jwt_audience,
            "jti": f"{user.id}-{now_ts}-{uuid4()}",
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return TokenResult(token, payload)

    def decode_token(self, token: str) -> Dict[str, Any]:
        """Validate signature, algorithm, expiry, issuer and audience; return the payload.

        Aborts the request with 401 on any validation failure.
        """
        try:
            payload = jwt.decode(
                token,
                key=self.jwt_secret,
                algorithms=[self.jwt_algorithm],
                audience=self.jwt_audience,
                issuer=self.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            abort(401, "Token expired")
        except jwt.InvalidAudienceError:
            abort(401, "Invalid token audience")
        except jwt.InvalidIssuerError:
            abort(401, "Invalid token issuer")
        except jwt.InvalidSignatureError:
            abort(401, "Invalid token signature")
        except jwt.InvalidTokenError:
            abort(401, "Invalid token")

        iat = payload.get("iat")
        now_ts = int(datetime.now(UTC).timestamp())
        if not isinstance(iat, (int, float)) or iat > now_ts + IAT_LEEWAY_SECONDS:
            abort(401, "Invalid token issued-at time")

        return payload

    def resolve_user(self, token: str, db_service) -> User:
        """Validate a bearer token and load the still-existing, still-active user.

        The database remains the authoritative source for role/active status:
        the role embedded in the token is never trusted here.
        """
        payload = self.decode_token(token)

        user_id_raw = payload.get("sub")
        try:
            user_id = int(user_id_raw)
        except (TypeError, ValueError):
            abort(401, "Invalid token")

        user = db_service.user_get_by_id(user_id)
        if user is None:
            abort(401, "Invalid or expired token")
        if not user.is_active:
            abort(401, "Invalid or expired token")

        return user
