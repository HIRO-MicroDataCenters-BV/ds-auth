# ds-auth

Standard authentication + authorization middleware for every Hiro dataspace
service. Verifies JWTs, resolves per-request permissions via the policy
engine, and injects identity headers downstream.

**One import, one `add_middleware` call per service** — nothing else to do.

## What it does

Per request:

1. Reads `Authorization: Bearer <JWT>`
2. Verifies the JWT's signature + issuer + audience + expiry against the
   verify service's published JWKs (cached for 5 minutes by default)
3. Looks up the permission required for `(method, path)` from the service's
   declared permission map
4. Calls `ds-policy-engine`'s `/api/v1/policies/evaluate` with the user's
   claims and the required permission
5. If the policy engine grants the permission, injects `X-User-AID`,
   `X-User-Role`, `X-User-Institute`, `X-User-Name`, `X-User-Email`,
   `X-Auth-Method` into the request and forwards to the service
6. Otherwise returns 401 (bad token) or 403 (policy denied) with a clear
   JSON detail

ACDC credential verification is a login-time concern — the verify service
does that once per session, and the claims it extracts travel in the JWT.
This middleware never re-verifies the credential; it trusts the JWT.

## Install

```bash
pip install ds-auth
```

Pin a version in your service's `pyproject.toml`.

## Use

```python
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
        ("GET",    r"^/datasets/?$",            "catalog:read"),
        ("POST",   r"^/datasets/[^/]+/?$",      "catalog:create"),
        ("DELETE", r"^/datasets/[^/]+/?$",      "catalog:delete"),
        ("POST",   r"^/datasets/[^/]+/share/?$","catalog:update"),
    ],
    public_paths=["/health-check/", "/metrics"],
)
```

That's the whole integration. The service does **not** write auth code.

## Reading identity in your service

The middleware injects headers; your handlers read them like any other:

```python
from fastapi import Header

@app.get("/datasets/{dataset_id}")
def get_dataset(
    dataset_id: str,
    x_user_aid: str | None = Header(default=None),
    x_user_role: str | None = Header(default=None),
    x_user_institute: str | None = Header(default=None),
):
    # middleware guaranteed catalog:read for this role — do fine-grained
    # service-specific checks here if needed:
    if dataset.owner_institute != x_user_institute and not is_public(dataset):
        raise HTTPException(403, "cross-institute access denied")
    return dataset
```

## Config

| Argument | Required | Description |
|---|---|---|
| `jwks_url` | yes | Where to fetch the JWT signing public keys |
| `issuer` | yes | Expected JWT `iss` claim |
| `audience` | yes | Expected JWT `aud` claim |
| `policy_engine_url` | yes | Base URL of `ds-policy-engine` |
| `permission_map` | yes | List of `(method, path_regex, permission)` tuples; first match wins |
| `public_paths` | no | Paths that skip auth entirely. Defaults cover `/health`, `/metrics`, `/docs`, `/openapi.json`. |
| `allow_unmapped` | no | If `True`, unmapped routes pass through unauthenticated. Default `False` (deny by default). |
| `header_prefix` | no | Prefix for injected identity headers. Default `"X-User"`. |

## Error responses

- `401 { "detail": "..." }` — missing / malformed / expired JWT, or JWKs lookup failed
- `403 { "detail": "policy denied", "required": "catalog:create", "granted": ["catalog:read"], "role": "...", "institute": "..." }`
- `503 { "detail": "..." }` — policy engine unreachable

## Testing locally

```bash
pip install -e ".[dev]"
pytest
```

Tests use `respx` to mock the JWKs endpoint and policy engine — no live services needed.

## How this fits the dataspace architecture

```
     USER
       │ Bearer JWT
       ▼
   service: ds-catalog / ds-search / ds-connector / ds-contract / ...
       │
       │ DataspaceAuthMiddleware (this package)
       ├──► verify JWT (JWKs cached from byok-verify)
       ├──► POST ds-policy-engine/api/v1/policies/evaluate
       └──► inject X-User-AID, X-User-Role, X-User-Institute headers
       │
       ▼
   service handler
       (does fine-grained business checks if needed)
```

## Versioning

Pin a version in your service. Breaking changes bump the major version.

## License

Apache-2.0
