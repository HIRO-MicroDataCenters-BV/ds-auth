"""The ASGI middleware — the one thing every dataspace service imports."""
from __future__ import annotations

import logging
from typing import Any, Iterable

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from .exceptions import (
    AuthError,
    InvalidTokenError,
    MissingTokenError,
    PolicyDeniedError,
    PolicyEngineUnavailableError,
)
from .jwks import JwksClient, JwtVerifier
from .permissions import PermissionMap, PermissionRule
from .policy import PolicyClient


logger = logging.getLogger("ds_auth")


class DataspaceAuthMiddleware(BaseHTTPMiddleware):
    """Standard RBAC middleware for every Hiro dataspace service.

    Flow per request:
      1. If path is in `public_paths`, pass through without auth.
      2. Extract Bearer JWT from Authorization header → 401 if missing/malformed.
      3. Verify JWT signature + iss + aud + exp against cached JWKs → 401 if invalid.
      4. Look up required permission from (method, path) → 403 if route unmapped
         (deny-by-default; see `allow_unmapped=True` to flip).
      5. Call policy engine with (name, email, role, institute) + required perm.
      6. If allowed, inject X-User-* headers into the request and forward.
      7. If not allowed, return 403 with the policy engine's decision info.
    """

    DEFAULT_PUBLIC_PATHS: tuple[str, ...] = (
        "/health",
        "/health-check",
        "/health-check/",
        "/metrics",
        "/openapi.json",
        "/docs",
        "/redoc",
    )

    def __init__(
        self,
        app: ASGIApp,
        *,
        jwks_url: str,
        issuer: str,
        audience: str,
        policy_engine_url: str,
        permission_map: Iterable[PermissionRule | tuple[str, str, str]] | PermissionMap,
        public_paths: Iterable[str] | None = None,
        allow_unmapped: bool = False,
        header_prefix: str = "X-User",
    ):
        super().__init__(app)

        # Permission map
        if isinstance(permission_map, PermissionMap):
            self.permission_map = permission_map
        else:
            self.permission_map = PermissionMap(permission_map)

        # Public paths
        if public_paths is None:
            self.public_paths = set(self.DEFAULT_PUBLIC_PATHS)
        else:
            self.public_paths = set(public_paths)

        self.allow_unmapped = allow_unmapped
        self.header_prefix = header_prefix.rstrip("-")

        # Auth clients
        self.jwt_verifier = JwtVerifier(
            jwks_client=JwksClient(jwks_url),
            issuer=issuer,
            audience=audience,
        )
        self.policy_client = PolicyClient(policy_engine_url)

    # ───────── main entry ─────────
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if self._is_public(path):
            return await call_next(request)

        # 1. JWT verification
        try:
            claims = self._verify_bearer(request)
        except AuthError as e:
            return self._error_response(e)

        # 2. Permission lookup
        required = self.permission_map.resolve(request.method, path)
        if required is None:
            if self.allow_unmapped:
                return await self._forward(request, claims, call_next)
            return self._error_response(
                PolicyDeniedError(
                    f"no permission mapping for {request.method} {path} "
                    f"(deny by default)"
                )
            )

        # 3. Policy engine check
        try:
            allowed, decision = self.policy_client.check(claims, required)
        except PolicyEngineUnavailableError as e:
            return self._error_response(e)

        if not allowed:
            return self._denied_response(decision)

        # 4. Forward with identity headers
        return await self._forward(request, claims, call_next)

    # ───────── helpers ─────────
    def _is_public(self, path: str) -> bool:
        return path in self.public_paths

    def _verify_bearer(self, request: Request) -> dict[str, Any]:
        auth = request.headers.get("authorization", "")
        if not auth:
            raise MissingTokenError("missing Authorization header")
        if not auth.lower().startswith("bearer "):
            raise InvalidTokenError("Authorization must use the Bearer scheme")
        token = auth.split(" ", 1)[1].strip()
        if not token:
            raise InvalidTokenError("empty bearer token")
        return self.jwt_verifier.verify(token)

    async def _forward(self, request: Request, claims: dict[str, Any], call_next):
        """Inject identity headers and pass to the service."""
        # Starlette headers are immutable; mutate the raw ASGI scope headers list.
        headers = list(request.scope.get("headers", []))
        for claim_name, header_suffix in (
            ("sub", "AID"),
            ("name", "Name"),
            ("email", "Email"),
            ("role", "Role"),
            ("institute", "Institute"),
            ("auth_method", "Auth-Method"),
            ("credential_said", "Credential-SAID"),
        ):
            value = claims.get(claim_name)
            if value:
                header_name = f"{self.header_prefix}-{header_suffix}".lower().encode("latin-1")
                header_value = str(value).encode("latin-1")
                # Remove any pre-existing header the client may have tried to inject
                headers = [(n, v) for (n, v) in headers if n != header_name]
                headers.append((header_name, header_value))
        request.scope["headers"] = headers

        return await call_next(request)

    @staticmethod
    def _error_response(err: AuthError) -> Response:
        body = {"detail": err.detail}
        return JSONResponse(status_code=err.status_code, content=body)

    @staticmethod
    def _denied_response(decision: dict[str, Any]) -> Response:
        body = {"detail": "policy denied", **decision}
        return JSONResponse(status_code=403, content=body)
