"""ds-auth — the standard auth + policy middleware for every
Hiro dataspace service.

Usage (in any service's main.py):

    from fastapi import FastAPI
    from ds_auth import DataspaceAuthMiddleware

    app = FastAPI()
    app.add_middleware(
        DataspaceAuthMiddleware,
        jwks_url="http://byok-verify:8080/.well-known/jwks.json",
        issuer="hiro-verify-service",
        audience="hiro-services",
        policy_engine_url="http://ds-policy-engine:8000",
        permission_map=[
            ("GET",    r"^/datasets/?$",      "catalog:read"),
            ("POST",   r"^/datasets/[^/]+/?$", "catalog:create"),
        ],
        public_paths=["/health-check/", "/metrics"],
    )

The middleware:
  1. Verifies the Bearer JWT against JWKs fetched from the verify service.
  2. Determines the required permission for the request based on method + path.
  3. Calls the policy engine with (name, email, role, institute) + the required
     permission; grants or denies based on the policy engine's response.
  4. On grant, injects X-User-* headers into the request so the downstream
     service can attribute changes and apply any fine-grained business logic.

ACDC credential verification is a login-time concern handled by the verify
service — the claims it produces are carried in the JWT and consumed here.
"""
from .middleware import DataspaceAuthMiddleware
from .permissions import PermissionRule, PermissionMap
from .exceptions import (
    AuthError,
    MissingTokenError,
    InvalidTokenError,
    PolicyDeniedError,
    PolicyEngineUnavailableError,
)

__version__ = "0.1.0"

__all__ = [
    "DataspaceAuthMiddleware",
    "PermissionRule",
    "PermissionMap",
    "AuthError",
    "MissingTokenError",
    "InvalidTokenError",
    "PolicyDeniedError",
    "PolicyEngineUnavailableError",
    "__version__",
]
