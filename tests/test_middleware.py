"""Integration-style tests for DataspaceAuthMiddleware against a FastAPI app
with a mocked JWKs endpoint and a mocked policy engine."""
import time
import uuid

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from ds_auth import DataspaceAuthMiddleware

# ──────── Test fixtures ────────

JWKS_URL = "http://verify.test/.well-known/jwks.json"
POLICY_URL = "http://policy.test"
ISSUER = "hiro-verify-test"
AUDIENCE = "hiro-services"


@pytest.fixture
def signing_setup():
    """Generate an RSA key, build the JWKs doc, provide a factory for signed JWTs."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = uuid.uuid4().hex[:16]

    pub_numbers = private_key.public_key().public_numbers()

    def _b64u(n: int) -> str:
        import base64
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    jwks_doc = {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": _b64u(pub_numbers.n),
            "e": _b64u(pub_numbers.e),
        }]
    }

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    def make_jwt(**claims_override):
        now = int(time.time())
        claims = {
            "sub": "EUserAID1234567890",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 900,
            "name": "Sai",
            "email": "sai@hiro.test",
            "role": "catalog_owner",
            "institute": "local",
            "auth_method": "keri-byok",
        }
        claims.update(claims_override)
        return pyjwt.encode(claims, priv_pem, algorithm="RS256", headers={"kid": kid})

    return jwks_doc, make_jwt


def build_app():
    app = FastAPI()
    app.add_middleware(
        DataspaceAuthMiddleware,
        jwks_url=JWKS_URL,
        issuer=ISSUER,
        audience=AUDIENCE,
        policy_engine_url=POLICY_URL,
        permission_map=[
            ("GET", r"^/items/?$", "catalog:read"),
            ("POST", r"^/items/?$", "catalog:create"),
        ],
        public_paths=["/health"],
    )

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/items")
    def list_items(x_user_aid: str | None = Header(default=None)):
        return {"items": [], "attributed_to": x_user_aid}

    @app.post("/items")
    def create_item(x_user_aid: str | None = Header(default=None)):
        return {"owner_aid": x_user_aid}

    return app


# ──────── Tests ────────

@respx.mock
def test_health_is_public(signing_setup):
    _ = signing_setup
    app = build_app()
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200


@respx.mock
def test_missing_token_returns_401(signing_setup):
    _ = signing_setup
    app = build_app()
    client = TestClient(app)
    r = client.get("/items")
    assert r.status_code == 401
    assert "Authorization" in r.json()["detail"]


@respx.mock
def test_malformed_token_returns_401(signing_setup):
    jwks_doc, _ = signing_setup
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_doc))

    app = build_app()
    client = TestClient(app)
    r = client.get("/items", headers={"Authorization": "Bearer not.a.real.jwt"})
    assert r.status_code == 401


@respx.mock
def test_valid_token_but_policy_denies_returns_403(signing_setup):
    jwks_doc, make_jwt = signing_setup
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_doc))
    respx.post(f"{POLICY_URL}/api/v1/policies/evaluate").mock(
        return_value=httpx.Response(200, json={"status": "success", "data": {"permissions": ["catalog:read"]}})
    )

    token = make_jwt()
    app = build_app()
    client = TestClient(app)
    # POST needs catalog:create, but policy only grants catalog:read
    r = client.post("/items", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    body = r.json()
    assert body["required"] == "catalog:create"
    assert body["granted"] == ["catalog:read"]


@respx.mock
def test_valid_token_and_permission_granted_forwards_with_headers(signing_setup):
    jwks_doc, make_jwt = signing_setup
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_doc))
    respx.post(f"{POLICY_URL}/api/v1/policies/evaluate").mock(
        return_value=httpx.Response(200, json={"status": "success", "data": {"permissions": [
            "catalog:read", "catalog:create", "catalog:update", "catalog:delete"
        ]}})
    )

    token = make_jwt(sub="EOwnerAID")
    app = build_app()
    client = TestClient(app)
    r = client.get("/items", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["attributed_to"] == "EOwnerAID"


@respx.mock
def test_unmapped_route_denied_by_default(signing_setup):
    jwks_doc, make_jwt = signing_setup
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_doc))

    app = FastAPI()
    app.add_middleware(
        DataspaceAuthMiddleware,
        jwks_url=JWKS_URL,
        issuer=ISSUER,
        audience=AUDIENCE,
        policy_engine_url=POLICY_URL,
        permission_map=[],  # no routes mapped
        public_paths=["/health"],
    )

    @app.get("/anything")
    def anything():
        return {"ok": True}

    @app.get("/health")
    def health():
        return {"ok": True}

    token = make_jwt()
    client = TestClient(app)
    r = client.get("/anything", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert "no permission mapping" in r.json()["detail"]


@respx.mock
def test_jwks_rotation_recovers(signing_setup):
    """If the signing kid changes, the middleware should re-fetch JWKs on the next request."""
    jwks_doc, make_jwt = signing_setup
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_doc))
    respx.post(f"{POLICY_URL}/api/v1/policies/evaluate").mock(
        return_value=httpx.Response(200, json={"status": "success", "data": {"permissions": ["catalog:read"]}})
    )

    app = build_app()
    client = TestClient(app)
    token = make_jwt()
    r = client.get("/items", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
