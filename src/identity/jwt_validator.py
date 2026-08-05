"""
JWT validation for the AegisAI identity subsystem.

This module validates cryptographic trust, issuer, audience, expiration,
token type, and required identity claims before identity context is built.
"""

from collections.abc import Mapping
from typing import Any

import jwt
from jwt import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from .exceptions import (
    MissingClaimError,
    TokenExpiredError,
    TokenValidationError,
)


_REQUIRED_CLAIMS = (
    "sub",
    "username",
    "email",
    "department",
    "role",
    "clearance",
    "iss",
    "aud",
    "exp",
    "iat",
    "token_use",
)


class JWTValidator:
    """
    Validates signed JWTs before AegisAI trusts their identity claims.
    """

    def __init__(
        self,
        *,
        public_key: str,
        issuer: str,
        audience: str,
        algorithm: str = "RS256",
        required_token_use: str = "access",
        leeway_seconds: int = 30,
    ) -> None:
        if not public_key.strip():
            raise ValueError("public_key must be provided")

        if not issuer.strip():
            raise ValueError("issuer must be provided")

        if not audience.strip():
            raise ValueError("audience must be provided")

        if algorithm not in {"RS256", "RS384", "RS512"}:
            raise ValueError("Only approved RSA signing algorithms are allowed")

        if required_token_use not in {"access", "id"}:
            raise ValueError("required_token_use must be 'access' or 'id'")

        if leeway_seconds < 0:
            raise ValueError("leeway_seconds cannot be negative")

        self._public_key = public_key
        self._issuer = issuer
        self._audience = audience
        self._algorithm = algorithm
        self._required_token_use = required_token_use
        self._leeway_seconds = leeway_seconds

    def validate(self, token: str) -> Mapping[str, Any]:
        """
        Validate a signed JWT and return trusted claims.

        Raises:
            TokenExpiredError:
                If the token is expired.
            MissingClaimError:
                If a required claim is missing.
            TokenValidationError:
                If the token fails any other trust check.
        """
        if not isinstance(token, str) or not token.strip():
            raise TokenValidationError("JWT must be a non-empty string")

        try:
            claims = jwt.decode(
                token,
                key=self._public_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway_seconds,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise TokenExpiredError("JWT has expired") from exc
        except MissingRequiredClaimError as exc:
            raise MissingClaimError(
                f"JWT is missing a required claim: {exc.claim}"
            ) from exc
        except ImmatureSignatureError as exc:
            raise TokenValidationError("JWT is not yet valid") from exc
        except InvalidIssuerError as exc:
            raise TokenValidationError("JWT issuer is invalid") from exc
        except InvalidAudienceError as exc:
            raise TokenValidationError("JWT audience is invalid") from exc
        except InvalidSignatureError as exc:
            raise TokenValidationError("JWT signature is invalid") from exc
        except InvalidTokenError as exc:
            raise TokenValidationError("JWT validation failed") from exc

        self._validate_token_use(claims)
        self._validate_identity_claims(claims)

        return claims

    def _validate_token_use(self, claims: Mapping[str, Any]) -> None:
        token_use = claims.get("token_use")

        if token_use != self._required_token_use:
            raise TokenValidationError(
                "JWT token_use does not match the required token type"
            )

    @staticmethod
    def _validate_identity_claims(claims: Mapping[str, Any]) -> None:
        """
        Ensure required identity claims contain non-empty strings.
        """
        string_claims = (
            "sub",
            "username",
            "email",
            "department",
            "role",
            "clearance",
        )

        for claim_name in string_claims:
            value = claims.get(claim_name)

            if not isinstance(value, str) or not value.strip():
                raise MissingClaimError(
                    f"JWT identity claim is missing or invalid: {claim_name}"
                )
