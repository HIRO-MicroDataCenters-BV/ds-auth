"""Mock ds-login — issues RS256 JWTs that match the shape of real ds-login.

Produces tokens with the same claim set a real ds-login would produce, from
hardcoded test identities. Signing key is RSA, generated at startup; JWKs
exposed at `/.well-known/jwks.json`.

For tests only. Not a replacement for ds-login in any other context.
"""
from __future__ import annotations

import base64
import json
import time
import uuid

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# Hardcoded test identities — the role/institute drives the policy decision
TEST_USERS: dict[str, dict[str, str]] = {
    "EOwnerAID": {
        "name": "Sai Owner",
        "email": "sai@hiro.test",
        "role": "catalog_owner",
        "institute": "local",
    },
    "EResearcherAID": {
        "name": "Alice Researcher",
        "email": "alice@hiro.test",
        "role": "researcher",
        "institute": "hiro",
    },
    "EConsumerAID": {
        "name": "Bob Consumer",
        "email": "bob@hiro.test",
        "role": "catalog_consumer",
        "institute": "local",
    },
}


# ──────── Signing setup ────────
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_kid = uuid.uuid4().hex[:16]
_private_pem = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


app = FastAPI(title="mock-ds-login", version="0.0.1")


# ──────── Models ────────
class IssueRequest(BaseModel):
    aid: str


class IssueResponse(BaseModel):
    jwt: str
    claims: dict


# ──────── Routes ────────
@app.get("/health-check/")
def health():
    return {"status": "OK"}


@app.get("/.well-known/jwks.json")
def jwks():
    pub = _private_key.public_key().public_numbers()

    def _b64u(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": _kid,
                "n": _b64u(pub.n),
                "e": _b64u(pub.e),
            }
        ]
    }


@app.post("/mock/issue", response_model=IssueResponse)
def issue(req: IssueRequest):
    """Issue a JWT for one of the hardcoded test AIDs."""
    if req.aid not in TEST_USERS:
        raise HTTPException(status_code=404, detail=f"unknown test AID: {req.aid}")
    profile = TEST_USERS[req.aid]
    now = int(time.time())
    claims = {
        "sub": req.aid,
        "iss": "ds-login",
        "aud": "hiro-services",
        "iat": now,
        "exp": now + 900,
        "auth_method": "keri-byok",
        **profile,
    }
    token = pyjwt.encode(claims, _private_pem, algorithm="RS256", headers={"kid": _kid})
    return IssueResponse(jwt=token, claims=claims)


@app.get("/mock/users")
def list_users():
    """Debug: list hardcoded test users."""
    return TEST_USERS
