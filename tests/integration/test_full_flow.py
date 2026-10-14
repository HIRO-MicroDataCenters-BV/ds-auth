"""Integration test — ds-auth against real ds-policy-engine + mocked ds-login.

Each test exercises the full chain: mock-ds-login issues a JWT, the test
calls the test-service over HTTP with the JWT, test-service's ds-auth
middleware verifies the JWT against JWKs and calls the real policy engine
for the per-request decision.
"""
import httpx


SERVICE_URL = "http://localhost:19100"


def test_health_check_is_public(policy_rules_deployed):
    r = httpx.get(f"{SERVICE_URL}/health-check/", timeout=5)
    assert r.status_code == 200
    assert r.json() == {"status": "OK"}


def test_no_token_returns_401(policy_rules_deployed):
    r = httpx.get(f"{SERVICE_URL}/items", timeout=5)
    assert r.status_code == 401
    assert "Authorization" in r.json().get("detail", "")


def test_owner_can_read(policy_rules_deployed, jwt_for):
    jwt = jwt_for("EOwnerAID")
    r = httpx.get(f"{SERVICE_URL}/items", headers={"Authorization": f"Bearer {jwt}"}, timeout=5)
    assert r.status_code == 200
    body = r.json()
    # ds-auth should have injected X-User-* headers, which the service echoes
    assert body["attributed_to"]["aid"] == "EOwnerAID"
    assert body["attributed_to"]["role"] == "catalog_owner"
    assert body["attributed_to"]["institute"] == "local"


def test_owner_can_create(policy_rules_deployed, jwt_for):
    jwt = jwt_for("EOwnerAID")
    r = httpx.post(
        f"{SERVICE_URL}/items",
        headers={"Authorization": f"Bearer {jwt}"},
        json={"title": "new dataset"},
        timeout=5,
    )
    assert r.status_code == 201
    assert r.json()["owner_aid"] == "EOwnerAID"


def test_researcher_can_read_but_not_create(policy_rules_deployed, jwt_for):
    jwt = jwt_for("EResearcherAID")

    # read is permitted
    r = httpx.get(f"{SERVICE_URL}/items", headers={"Authorization": f"Bearer {jwt}"}, timeout=5)
    assert r.status_code == 200

    # create is denied — policy only grants catalog:read
    r = httpx.post(
        f"{SERVICE_URL}/items",
        headers={"Authorization": f"Bearer {jwt}"},
        json={"title": "attempt"},
        timeout=5,
    )
    assert r.status_code == 403
    body = r.json()
    assert body["detail"] == "policy denied"
    assert body["required"] == "catalog:create"
    assert "catalog:read" in body["granted"]


def test_researcher_cannot_delete(policy_rules_deployed, jwt_for):
    jwt = jwt_for("EResearcherAID")
    r = httpx.delete(
        f"{SERVICE_URL}/items/demo-1",
        headers={"Authorization": f"Bearer {jwt}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert r.json()["required"] == "catalog:delete"


def test_consumer_can_read(policy_rules_deployed, jwt_for):
    jwt = jwt_for("EConsumerAID")
    r = httpx.get(f"{SERVICE_URL}/items", headers={"Authorization": f"Bearer {jwt}"}, timeout=5)
    assert r.status_code == 200


def test_consumer_cannot_create(policy_rules_deployed, jwt_for):
    jwt = jwt_for("EConsumerAID")
    r = httpx.post(
        f"{SERVICE_URL}/items",
        headers={"Authorization": f"Bearer {jwt}"},
        json={"title": "x"},
        timeout=5,
    )
    assert r.status_code == 403


def test_malformed_bearer_returns_401(policy_rules_deployed):
    r = httpx.get(
        f"{SERVICE_URL}/items",
        headers={"Authorization": "Bearer not.a.jwt.at.all"},
        timeout=5,
    )
    assert r.status_code == 401


def test_wrong_scheme_returns_401(policy_rules_deployed):
    r = httpx.get(
        f"{SERVICE_URL}/items",
        headers={"Authorization": "Basic abc123"},
        timeout=5,
    )
    assert r.status_code == 401


def test_unmapped_route_denied_by_default(policy_rules_deployed, jwt_for):
    """ds-auth defaults to deny on unmapped routes — a route the service doesn't
    declare a permission for returns 403, not an accidental 200."""
    jwt = jwt_for("EOwnerAID")
    r = httpx.get(
        f"{SERVICE_URL}/unmapped-endpoint",
        headers={"Authorization": f"Bearer {jwt}"},
        timeout=5,
    )
    assert r.status_code == 403
    assert "no permission mapping" in r.json()["detail"]
