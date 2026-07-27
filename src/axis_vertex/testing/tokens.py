"""Token factory for SDK tests and examples."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


class TokenFactory:
    """Generate RS256 Java IAM-like tokens and matching JWKS."""

    def __init__(self, *, issuer: str, audience: str, kid: str = "test-kid") -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.kid = kid
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self) -> dict[str, Any]:
        """Return the public JWKS."""

        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self._private_key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def issue_token(
        self,
        subject: str = "user-1",
        *,
        roles: list[str] | None = None,
        expires_delta: timedelta = timedelta(minutes=10),
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Issue a signed access token."""

        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "sub": subject,
            "aud": self.audience,
            "iss": self.issuer,
            "roles": roles or [],
            "iat": now,
            "exp": now + expires_delta,
        }
        if extra_claims:
            payload.update(extra_claims)
        token = jwt.encode(
            payload,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self.kid, "typ": "JWT"},
        )
        return token
