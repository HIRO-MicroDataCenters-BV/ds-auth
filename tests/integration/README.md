# ds-auth integration tests

End-to-end verification of `ds-auth` against the real `ds-policy-engine` + a
mock `ds-login` (JWT issuer) and a tiny service that uses `ds-auth` as its
auth middleware.

## What this covers

The unit tests in `../test_middleware.py` mock everything. These tests put real
containers in front of ds-auth so we catch integration bugs:

- JWKs discovery and caching from a live JWT issuer
- JWT signature verification against RS256 keys from JWKs
- Policy engine round-trip (OPA-backed, real Rego policies)
- Header injection and downstream propagation
- 401 / 403 / 200 outcomes against real responses

## Stack

```
                       ┌──────────────────────┐
                       │   mock-ds-login      │  :8080
                       │   issues RS256 JWTs  │
                       └──────────┬───────────┘
                                  │ /.well-known/jwks.json
                                  ▼
    USER ──Bearer JWT──▶  test-service        :9100
                          (uses ds-auth
                           middleware)
                                  │ POST /api/v1/policies/evaluate
                                  ▼
                       ┌──────────────────────┐
                       │  ds-policy-engine    │  :8000
                       │  (real GHCR image)   │
                       └──────────┬───────────┘
                                  │ OPA data API
                                  ▼
                       ┌──────────────────────┐
                       │  ds-opa              │  :8181
                       │  (real OPA)          │
                       └──────────────────────┘
```

## Why ds-login is mocked here (not real)

ds-login's unique responsibilities — ACDC verification, witness/watcher
queries — are tested in **ds-login's own repo**. ds-auth cares only that the
JWTs are issued correctly and verifiable via JWKs. The mock issues
identical-shape JWTs with controllable claims so we can test role variations
without having to spin up KERI witnesses in CI.

## Run locally

```bash
cd tests/integration
docker compose up -d --build
# wait for health
docker compose ps
# then
cd ../..
pytest tests/integration -v
# cleanup
cd tests/integration && docker compose down -v
```

The pytest fixture `compose_stack` does all three steps automatically; the
manual sequence above is for debugging.

## Run in CI

The `integration` workflow (`.github/workflows/integration.yaml`) runs this
suite on every push to `develop` and on PRs targeting `develop`.
