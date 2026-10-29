"""Auth-service client-credentials verification for Skills policy calls."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import jwt
from jwt import PyJWKClient

WORKLOAD_SCOPE = "policy.evaluate:skills"
REVOCATION_SLO_SECONDS = 60


class WorkloadIdentityError(Exception):
    """A bounded workload-token verification failure."""


class JWKSWorkloadIdentityVerifier:
    """Verify short-lived RS256 service tokens using auth-service JWKS."""

    def __init__(
        self,
        jwks_client_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self._factory = jwks_client_factory or (
            lambda url: PyJWKClient(
                url,
                cache_jwk_set=True,
                cache_keys=False,
                lifespan=REVOCATION_SLO_SECONDS,
                timeout=0.75,
            )
        )
        self._clients: dict[str, Any] = {}

    def verify(
        self,
        token: str | None,
        *,
        jwks_url: str,
        issuer: str,
        audience: str,
        trusted_clients: frozenset[str],
        tenant_id: str,
        now: datetime,
    ) -> str:
        if not token:
            raise WorkloadIdentityError("workload token is missing")
        if not jwks_url or not issuer or audience != "policy-engine":
            raise WorkloadIdentityError("workload verifier is not configured")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise WorkloadIdentityError("workload token algorithm is invalid")
            client = self._clients.setdefault(jwks_url, self._factory(jwks_url))
            key = client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=audience,
                issuer=issuer,
                leeway=5,
                options={
                    "require": [
                        "aud",
                        "iss",
                        "exp",
                        "iat",
                        "jti",
                        "type",
                        "auth_method",
                        "client_id",
                        "org_id",
                        "scopes",
                    ]
                },
            )
        except WorkloadIdentityError:
            raise
        except Exception as exc:
            raise WorkloadIdentityError("workload token verification failed") from exc

        client_id = claims.get("client_id")
        scopes = claims.get("scopes")
        if claims.get("aud") != "policy-engine":
            raise WorkloadIdentityError("workload token audience is invalid")
        if (
            claims.get("type") != "access"
            or claims.get("auth_method") != "client_credentials"
        ):
            raise WorkloadIdentityError(
                "token is not a client-credentials access token"
            )
        if "sub" in claims or "email" in claims:
            raise WorkloadIdentityError(
                "user tokens cannot authenticate policy workloads"
            )
        if not isinstance(client_id, str) or client_id not in trusted_clients:
            raise WorkloadIdentityError("workload client is not trusted")
        if not isinstance(scopes, list) or WORKLOAD_SCOPE not in scopes:
            raise WorkloadIdentityError("workload token scope is invalid")
        if str(claims.get("org_id")) != tenant_id:
            raise WorkloadIdentityError("workload tenant binding mismatch")
        issued_at = int(claims["iat"])
        expires_at = int(claims["exp"])
        current = int(now.astimezone(UTC).timestamp())
        if issued_at > current + 5:
            raise WorkloadIdentityError("workload token is future-dated")
        if expires_at - issued_at > REVOCATION_SLO_SECONDS:
            raise WorkloadIdentityError(
                "workload token lifetime exceeds revocation SLO"
            )
        if expires_at <= current:
            raise WorkloadIdentityError("workload token is expired")
        return client_id
