"""Policy engine client — calls ds-policy-engine to resolve what a user with
these claims is allowed to do, and checks whether a specific permission is in
the allowed set."""
from __future__ import annotations

from typing import Any

import httpx

from .exceptions import PolicyEngineUnavailableError


POLICY_EVALUATE_PATH = "/api/v1/policies/evaluate"


class PolicyClient:
    """Thin wrapper over the policy engine's /policies/evaluate endpoint.

    The policy engine today returns the full permissions set for the (role,
    institute) tuple; this client checks membership of the required permission.
    If the engine evolves to accept finer input (resource, action), the client
    can forward it transparently.
    """

    def __init__(self, policy_engine_url: str, http_timeout: float = 5.0,
                 required_claims: tuple[str, ...] = ("name", "email", "role", "institute")):
        self.base_url = policy_engine_url.rstrip("/")
        self.evaluate_url = self.base_url + POLICY_EVALUATE_PATH
        self.http_timeout = http_timeout
        self.required_claims = required_claims

    def check(self, claims: dict[str, Any], required_permission: str) -> tuple[bool, dict[str, Any]]:
        """Return (allowed, decision_info).

        Decision info carries the required permission, the full set of granted
        permissions, and the identity claims used for the decision — useful for
        the middleware to return in 403 bodies and for audit logging.
        """
        missing = [c for c in self.required_claims if not claims.get(c)]
        if missing:
            return False, {
                "reason": f"JWT missing required identity claims: {missing}",
                "required": required_permission,
            }

        payload = {k: claims[k] for k in self.required_claims}

        try:
            r = httpx.post(self.evaluate_url, json=payload, timeout=self.http_timeout)
        except httpx.HTTPError as e:
            raise PolicyEngineUnavailableError(
                f"could not reach policy engine at {self.evaluate_url}: {e}"
            ) from e

        if r.status_code != 200:
            return False, {
                "reason": f"policy engine returned HTTP {r.status_code}",
                "required": required_permission,
                "body": r.text[:400],
            }

        body = r.json()
        permissions = self._extract_permissions(body)
        if not isinstance(permissions, list):
            return False, {
                "reason": "policy engine response has no permissions list",
                "required": required_permission,
                "raw": body,
            }

        allowed = required_permission in permissions
        return allowed, {
            "required": required_permission,
            "granted": permissions,
            "role": claims["role"],
            "institute": claims["institute"],
        }

    @staticmethod
    def _extract_permissions(body: Any) -> list[str] | None:
        """ds-policy-engine wraps its response as {status, data: {permissions: [...]}}
        — but defend against future shapes."""
        if isinstance(body, dict):
            data = body.get("data")
            if isinstance(data, dict):
                perms = data.get("permissions") or data.get("allowed_permissions")
                if perms is not None:
                    return perms
            top = body.get("permissions")
            if top is not None:
                return top
        return None
