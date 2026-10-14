"""Example service showing how to use ds-auth.

Run:
    uvicorn example_service:app --port 9100

Then set these env vars (or edit the config below):
    HIRO_JWKS_URL        = http://localhost:8080/.well-known/jwks.json
    HIRO_POLICY_URL      = http://localhost:8000
    HIRO_JWT_ISSUER      = hiro-verify-service
    HIRO_JWT_AUDIENCE    = hiro-services
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header

from ds_auth import DataspaceAuthMiddleware


app = FastAPI(title="example-dataspace-service", version="0.0.1")

app.add_middleware(
    DataspaceAuthMiddleware,
    jwks_url=os.environ.get("HIRO_JWKS_URL", "http://localhost:8080/.well-known/jwks.json"),
    issuer=os.environ.get("HIRO_JWT_ISSUER", "hiro-verify-service"),
    audience=os.environ.get("HIRO_JWT_AUDIENCE", "hiro-services"),
    policy_engine_url=os.environ.get("HIRO_POLICY_URL", "http://localhost:8000"),
    permission_map=[
        ("GET",    r"^/items/?$",            "catalog:read"),
        ("GET",    r"^/items/[^/]+/?$",      "catalog:read"),
        ("POST",   r"^/items/?$",            "catalog:create"),
        ("PUT",    r"^/items/[^/]+/?$",      "catalog:update"),
        ("DELETE", r"^/items/[^/]+/?$",      "catalog:delete"),
    ],
    public_paths=["/health", "/openapi.json", "/docs"],
)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/items")
def list_items(
    x_user_aid: str | None = Header(default=None),
    x_user_role: str | None = Header(default=None),
    x_user_institute: str | None = Header(default=None),
):
    return {
        "items": [
            {"id": "demo-1", "title": "Sample dataset"},
            {"id": "demo-2", "title": "Another dataset"},
        ],
        "attributed_to": {"aid": x_user_aid, "role": x_user_role, "institute": x_user_institute},
    }


@app.post("/items")
def create_item(
    body: dict,
    x_user_aid: str | None = Header(default=None),
):
    return {"id": "demo-new", "owner_aid": x_user_aid, **body}
