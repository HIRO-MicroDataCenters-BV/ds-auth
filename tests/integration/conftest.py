"""Pytest fixtures that bring up the integration stack via docker compose."""
from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

COMPOSE_DIR = Path(__file__).parent
# Host-mapped ports (see docker-compose.yml); each service also has an in-cluster hostname
POLICY_URL = "http://localhost:18000"
LOGIN_URL = "http://localhost:18080"
SERVICE_URL = "http://localhost:19100"


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run `docker compose ...` in the integration directory."""
    cmd = ["docker", "compose", *args]
    return subprocess.run(
        cmd,
        cwd=str(COMPOSE_DIR),
        check=check,
        capture_output=True,
        text=True,
    )


def _wait_for(url: str, timeout_s: int = 90, interval_s: float = 1.0) -> None:
    """Poll until the URL returns 2xx or we give up."""
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if 200 <= r.status_code < 300:
                return
            last_err = RuntimeError(f"HTTP {r.status_code}")
        except (httpx.HTTPError, OSError) as e:
            last_err = e
        time.sleep(interval_s)
    raise RuntimeError(f"Timed out waiting for {url}: {last_err}")


@pytest.fixture(scope="session")
def compose_stack() -> Iterator[None]:
    """Session-scoped fixture that builds + starts the stack, yields, tears down."""
    if os.environ.get("DS_AUTH_IT_SKIP_COMPOSE") == "1":
        # Mode for debugging — caller is managing the stack themselves
        yield
        return

    _compose("up", "-d", "--build", "--quiet-pull")
    try:
        _wait_for(f"{LOGIN_URL}/health-check/", timeout_s=60)
        _wait_for(f"{POLICY_URL}/health", timeout_s=90)
        _wait_for(f"{SERVICE_URL}/health-check/", timeout_s=60)
        yield
    finally:
        if os.environ.get("DS_AUTH_IT_KEEP_STACK") != "1":
            _compose("down", "-v", check=False)


@pytest.fixture(scope="session")
def policy_rules_deployed(compose_stack) -> None:
    """Seed the policy engine with the rules our tests rely on, and deploy to OPA.

    Rules match the identities issued by `mock-ds-login`:
      * catalog_owner @ local  → full CRUD + search
      * researcher @ hiro      → catalog:read + search:execute
      * catalog_consumer @ local → catalog:read
    """
    # Create (or recreate) rules. Policy engine returns 409 if the name clashes;
    # for test determinism we wipe first via toggle+delete, but as the compose
    # stack starts clean each session it's enough to add.
    rules = [
        {
            "name": "it-owner-full",
            "description": "Integration test — catalog owner full access",
            "role": "catalog_owner",
            "institute": "local",
            "permissions": [
                "catalog:read", "catalog:create", "catalog:update", "catalog:delete",
            ],
        },
        {
            "name": "it-researcher-read",
            "description": "Integration test — researcher read only",
            "role": "researcher",
            "institute": "hiro",
            "permissions": ["catalog:read"],
        },
        {
            "name": "it-consumer-read",
            "description": "Integration test — consumer read",
            "role": "catalog_consumer",
            "institute": "local",
            "permissions": ["catalog:read"],
        },
    ]
    for rule in rules:
        r = httpx.post(f"{POLICY_URL}/api/v1/rules", json=rule, timeout=10)
        # Accept 201 (created) and 409 (already exists if a prior test session's data lingered)
        assert r.status_code in (200, 201, 409), (
            f"creating rule {rule['name']!r} failed: HTTP {r.status_code} {r.text[:200]}"
        )

    # Deploy — this is the step we hammered on in the sandbox demo: OPA
    # doesn't honour new rules until deploy triggers Rego regeneration.
    r = httpx.post(f"{POLICY_URL}/api/v1/policies/deploy", json={}, timeout=10)
    assert r.status_code == 200, (
        f"policy deploy failed: HTTP {r.status_code} {r.text[:200]}"
    )


@pytest.fixture
def jwt_for():
    """Factory: ask mock-ds-login for a JWT for one of the hardcoded test AIDs."""
    def _issue(aid: str) -> str:
        r = httpx.post(f"{LOGIN_URL}/mock/issue", json={"aid": aid}, timeout=5)
        r.raise_for_status()
        return r.json()["jwt"]
    return _issue
