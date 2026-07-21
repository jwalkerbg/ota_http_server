# core/auth.py

from typing import Any, Dict
from datetime import datetime, time, timedelta, timezone
from flask import request, abort, current_app as app
import jwt
import hmac

from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class AuthService:

    def __init__(self, use_jwt: bool, jwt_secret: str, jwt_algorithm: str, jwt_audience: str, jwt_issuer: str):
        self.use_jwt = use_jwt
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_audience = jwt_audience
        self.jwt_issuer = jwt_issuer

    def verify_token(self, project:str|None=None, verify_sub:bool=True) -> Dict[str, Any]:
        """Verifies JWT from Authorization header or ?token= query param.
        Allows query param only for safe (GET, HEAD) requests.
        Example token:
        {
            "expires_at": "2026-04-10T13:36:53+00:00",
            "payload": {
                "aud": "ota_api",                                           # who the request is targeted to (the OTA api)
                "download_vs": "01.20.01",                                  # the version the device is allowed to download
                "exp": 1775828213,                                          # expiration timestamp (UTC)
                "iat": 1775826413,                                          # issued at timestamp (UTC)
                "iss": "ota_http_server",
                "jti": "e6f87d77-4216-4be1-ab83-b5fa6792b747-1775826413",   # unique token identifier
                "project": "smart_air",                                     # the project the device is allowed to access
                "roles": [                                                  # the roles the device has, must include
                    "device",                                               # the device role
                    "fw_download"                                           # the firmware download role
                ],
                "sub": "e6f87d77-4216-4be1-ab83-b5fa6792b747"               # the device identity (UUID v4), must match the X-Device-ID header or ?device_id= query param
            }
        }

        params:
        {
            jwt_secret: str
            jwt_algorithm: str
            jwt_audience: str
            jwt_issuer: str
        }
        """
        if not self.use_jwt:
            return {}  # JWT authentication is disabled, allow all requests

        token = None
        source = None

        # 1️⃣ Try Authorization header first
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[len("Bearer "):]
            source = "header"

        # 2️⃣ Fallback to ?token= only if header missing
        if not token:
            token = request.args.get("token")
            if token:
                source = "query"
                # Allow query tokens only for safe requests (GET, HEAD)
                if request.method not in ("GET", "HEAD"):
                    abort(405, "Query token not allowed for this method")

        # 3️⃣ If no token found at all
        if not token:
            abort(401, "Missing token (Authorization header or ?token=)")

        # 4️⃣ Decode and verify JWT
        try:
            payload = jwt.decode(jwt=token, key=self.jwt_secret, algorithms=[self.jwt_algorithm], options={"verify_exp": True}, audience=self.jwt_audience, issuer=self.jwt_issuer)
        except jwt.ExpiredSignatureError:
            abort(401, "Token expired")
        except jwt.InvalidTokenError:
            abort(401, "Invalid token")

        # 5️⃣ Verify project match
        token_project = payload.get("project")
        if not project or not hmac.compare_digest(token_project, project):
            abort(403, "Token not valid for this project or project not given")

        # 5️⃣.1️⃣ Verify "roles" claim contains "device" and "fw_download"
        roles = payload.get("roles", [])
        if not all(role in roles for role in ("device", "fw_download")):
            abort(403, "Token does not have required roles")

        # 5️⃣.2️⃣ Verify "aud" claim is "ota_api"
        aud = payload.get("aud")
        if not aud or not hmac.compare_digest(aud, self.jwt_audience):
            abort(403, "Token not valid for this API")

        # 5️⃣.3️⃣ Verify issuer claim if present (optional, but good practice)
        issuer = payload.get("iss")
        expected_issuer = app.config.get("jwt_issuer", "ota_http_server")
        if issuer and not hmac.compare_digest(issuer, expected_issuer):
            abort(403, "Token issuer mismatch")

        # 5️⃣.4️⃣ Verify "sub" claim is present (device identity)
        if verify_sub:
            if "sub" not in payload:
                abort(403, "Token missing 'sub' claim for device identity")
            request_device_id = request.headers.get("X-Device-ID")
            if not request_device_id:
                request_device_id = request.args.get("device_id")  # Allow device_id in query param as fallback for GET requests
            if not request_device_id:
                abort(400, "Missing X-Device-ID header or device_id query parameter")
            if not hmac.compare_digest(payload["sub"], request_device_id):
                abort(403, "Token sub claim does not match X-Device-ID header")

        # 6️⃣ Log successful authentication
        device_id = payload.get("sub", "unknown")
        now = datetime.now(timezone.utc).isoformat()
        logger.info(f"[%s] [AUTH] OK - Device=%s, Project=%s, Source=%s", now, device_id, token_project, source)

        return payload
