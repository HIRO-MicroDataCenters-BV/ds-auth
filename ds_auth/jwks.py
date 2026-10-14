"""JWKs client — fetches and caches the verify service's public keys so JWTs can
be validated locally without a round-trip per request."""
from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

from .exceptions import InvalidTokenError

DEFAULT_CACHE_TTL = 300  # 5 minutes — matches byok-verify's typical signing-key stability


class JwksClient:
    """Fetches and caches public keys from a JWKs endpoint, keyed by `kid`."""

    def __init__(self, jwks_url: str, cache_ttl: int = DEFAULT_CACHE_TTL,
                 http_timeout: float = 5.0):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self.http_timeout = http_timeout
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0

    def _needs_refresh(self) -> bool:
        return (time.time() - self._fetched_at) >= self.cache_ttl or not self._keys

    def _fetch(self) -> dict[str, Any]:
        r = httpx.get(self.jwks_url, timeout=self.http_timeout)
        r.raise_for_status()
        return r.json()

    def _refresh(self) -> None:
        data = self._fetch()
        keys: dict[str, Any] = {}
        for jwk in data.get("keys", []):
            kid = jwk.get("kid")
            if kid is None:
                continue
            keys[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))
        self._keys = keys
        self._fetched_at = time.time()

    def key_for(self, kid: str, force_refresh: bool = False) -> Any:
        if force_refresh or self._needs_refresh():
            self._refresh()
        if kid not in self._keys:
            # One retry with a forced refresh in case the signing key rotated
            self._refresh()
        key = self._keys.get(kid)
        if key is None:
            raise InvalidTokenError(f"no public key for kid={kid!r} at {self.jwks_url}")
        return key


class JwtVerifier:
    """Verifies a Bearer token using cached JWKs and returns the decoded claims."""

    def __init__(
        self,
        jwks_client: JwksClient,
        issuer: str,
        audience: str,
        algorithms: list[str] | None = None,
        leeway_seconds: int = 10,
    ):
        self.jwks_client = jwks_client
        self.issuer = issuer
        self.audience = audience
        self.algorithms = algorithms or ["RS256"]
        self.leeway_seconds = leeway_seconds

    def verify(self, bearer_token: str) -> dict[str, Any]:
        try:
            header = pyjwt.get_unverified_header(bearer_token)
        except pyjwt.PyJWTError as e:
            raise InvalidTokenError(f"malformed JWT header: {e}") from e

        kid = header.get("kid")
        if not kid:
            raise InvalidTokenError("JWT header is missing the 'kid' field")

        key = self.jwks_client.key_for(kid)

        try:
            claims = pyjwt.decode(
                bearer_token,
                key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
            )
        except pyjwt.ExpiredSignatureError as e:
            raise InvalidTokenError("JWT expired") from e
        except pyjwt.InvalidAudienceError as e:
            raise InvalidTokenError(f"JWT audience mismatch (expected {self.audience!r})") from e
        except pyjwt.InvalidIssuerError as e:
            raise InvalidTokenError(f"JWT issuer mismatch (expected {self.issuer!r})") from e
        except pyjwt.PyJWTError as e:
            raise InvalidTokenError(f"JWT invalid: {e}") from e

        return claims
