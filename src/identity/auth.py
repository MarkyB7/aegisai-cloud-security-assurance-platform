"""
Authentication orchestration for the AegisAI identity subsystem.

This module connects JWT validation with identity-context construction.
"""

from collections.abc import Sequence
from typing import Any

from .exceptions import AuthenticationError, IdentityError
from .identity_context import build_identity_context
from .jwt_validator import JWTValidator
from .models import IdentityContext, Permission


class AuthenticationService:
    """
    Authenticates requests and creates trusted identity contexts.

    This service coordinates existing identity components. It does not
    implement JWT cryptography or authorization policy evaluation itself.
    """

    def __init__(self, *, jwt_validator: JWTValidator) -> None:
        if not isinstance(jwt_validator, JWTValidator):
            raise TypeError("jwt_validator must be a JWTValidator instance")

        self._jwt_validator = jwt_validator

    def authenticate(
        self,
        *,
        token: str,
        session_id: str,
        authorized: bool = False,
        permissions: Sequence[Permission] | None = None,
        allowed_models: Sequence[str] | None = None,
        allowed_tools: Sequence[str] | None = None,
        request_id: str | None = None,
    ) -> IdentityContext:
        """
        Validate a JWT and build a trusted identity context.

        Args:
            token:
                Signed JWT presented by the requester.
            session_id:
                Identifier associated with the requester session.
            authorized:
                Existing authorization result. This remains false until the
                authorization subsystem approves the requested action.
            permissions:
                Fine-grained permissions already granted to the identity.
            allowed_models:
                Models the identity may invoke.
            allowed_tools:
                Tools the identity may invoke.
            request_id:
                Correlation identifier for the current request.

        Returns:
            A validated and normalized IdentityContext.

        Raises:
            AuthenticationError:
                If authentication or identity-context creation fails.
        """
        try:
            claims = self._jwt_validator.validate(token)

            return build_identity_context(
                claims=claims,
                session_id=session_id,
                authorized=authorized,
                permissions=permissions,
                allowed_models=allowed_models,
                allowed_tools=allowed_tools,
                request_id=request_id,
            )
        except IdentityError:
            raise
        except (TypeError, ValueError) as exc:
            raise AuthenticationError(
                "Unable to build authenticated identity context"
            ) from exc


def extract_bearer_token(
    authorization_header: str | None,
) -> str:
    """
    Extract a JWT from an HTTP Authorization header.

    Expected format:
        Authorization: Bearer <token>

    Raises:
        AuthenticationError:
            If the header is missing or malformed.
    """
    if not isinstance(authorization_header, str):
        raise AuthenticationError("Authorization header is required")

    scheme, separator, credentials = authorization_header.strip().partition(" ")

    if not separator or scheme.lower() != "bearer":
        raise AuthenticationError(
            "Authorization header must use the Bearer scheme"
        )

    token = credentials.strip()

    if not token:
        raise AuthenticationError("Bearer token is missing")

    if any(character.isspace() for character in token):
        raise AuthenticationError("Bearer token is malformed")

    return token
