"""Tiny test service — the thing ds-auth is actually protecting.

Mirrors the shape of a real ds-* service: declare a permission map, let
ds-auth do all the auth work, read identity from injected headers.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Header

from ds_auth import DataspaceAuthMiddleware


app = FastAPI(title="test-service", version="0.0.1")


app.add_middleware(
    DataspaceAuthMiddleware,
    jwks_url=os.environ["HIRO_JWKS_URL"],
    issuer=os.environ.get("HIRO_JWT_ISSUER", "ds-login"),
    audience=os.environ.get("HIRO_JWT_AUDIENCE", "hiro-services"),
    policy_engine_url=os.environ["HIRO_POLICY_URL"],
    permission_map=[
        ("GET",    r"^/items/?$",            "catalog:read"),
        ("POST",   r"^/items/?$",            "catalog:create"),
        ("GET",    r"^/items/[^/]+/?$",      "catalog:read"),
        ("PUT",    r"^/items/[^/]+/?$",      "catalog:update"),
        ("DELETE", r"^/items/[^/]+/?$",      "catalog:delete"),
    ],
    public_paths=["/health-check/", "/metrics"],
)


@app.get("/health-check/")
def health():
    return {"status": "OK"}


@app.get("/items")
def list_items(
    x_user_aid: str | None = Header(default=None),
    x_user_role: str | None = Header(default=None),
    x_user_institute: str | None = Header(default=None),
):
    return {
        "items": [{"id": "demo-1", "title": "dataset-1"}],
        "attributed_to": {
            "aid": x_user_aid,
            "role": x_user_role,
            "institute": x_user_institute,
        },
    }


@app.post("/items", status_code=201)
def create_item(
    body: dict,
    x_user_aid: str | None = Header(default=None),
):
    return {"id": "demo-new", "owner_aid": x_user_aid, **body}


@app.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: str):
    return None
