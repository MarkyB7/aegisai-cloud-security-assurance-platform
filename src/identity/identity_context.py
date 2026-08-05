"""
Identity-context construction for the AegisAI identity subsystem.

This module converts validated identity claims and authorization results
into the standardized IdentityContext consumed by downstream services.
"""

from collections.abc import Mapping, Sequence
from typing import Any
from uuid import uuid4

from .exceptions import MissingClaimError
from .models import IdentityContext, Permission, UserIdentity


_REQUIRED_IDENTITY_CLAIMS = (
    "sub",
    "username",
    "email",
    "department",
    "role",
    "clearance",
)


def _require_string_claim(claims: Mapping[str, Any], name: str) -> str:
    """
    Return a required non-empty string claim.

    Raises:
        MissingClaimError: If the claim is missing, empty, or not a string.
    """
    value = claims.get(name)

    if not isinstance(value, str) or not value.strip():
        raise MissingClaimError(
            f"Required identity claim is missing or invalid: {name}"
        )

    return value.strip()


def _normalize_string_list(
    values: Sequence[str] | None,
    *,
    field_name: str,
) -> list[str]:
    """
    Normalize a sequence of strings while rejecting malformed values.
    """
    if values is None:
        return []

    normalized: list[str] = []

    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"{field_name} must contain only non-empty strings"
            )

        cleaned_value = value.strip()

        if cleaned_value not in normalized:
            normalized.append(cleaned_value)

    return normalized


def build_identity_context(
    *,
    claims: Mapping[str, Any],
    session_id: str,
    authorized: bool,
    permissions: Sequence[Permission] | None = None,
    allowed_models: Sequence[str] | None = None,
    allowed_tools: Sequence[str] | None = None,
    request_id: str | None = None,
) -> IdentityContext:
    """
    Build a validated IdentityContext for downstream AegisAI services.

    Args:
        claims:
            Validated identity-token claims. This function does not validate
            JWT signatures; it assumes cryptographic token validation has
            already succeeded.
        session_id:
            Identifier for the authenticated session.
        authorized:
            Result of the authorization decision.
        permissions:
            Fine-grained permissions granted to the identity.
        allowed_models:
            AI models the identity may invoke.
        allowed_tools:
            Enterprise tools the identity may invoke.
        request_id:
            Existing request correlation identifier. A new UUID is generated
            when one is not provided.

    Returns:
        A complete, normalized IdentityContext.

    Raises:
        MissingClaimError:
            If a required identity claim is absent or malformed.
        ValueError:
            If session or collection values are invalid.
    """
    for claim_name in _REQUIRED_IDENTITY_CLAIMS:
        _require_string_claim(claims, claim_name)

    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")

    normalized_request_id = request_id or str(uuid4())

    if not isinstance(normalized_request_id, str) or not normalized_request_id.strip():
        raise ValueError("request_id must be a non-empty string")

    identity = UserIdentity(
        user_id=_require_string_claim(claims, "sub"),
        username=_require_string_claim(claims, "username"),
        email=_require_string_claim(claims, "email"),
        department=_require_string_claim(claims, "department"),
        role=_require_string_claim(claims, "role"),
        clearance=_require_string_claim(claims, "clearance"),
    )

    return IdentityContext(
        identity=identity,
        authenticated=True,
        authorized=authorized,
        session_id=session_id.strip(),
        allowed_models=_normalize_string_list(
            allowed_models,
            field_name="allowed_models",
        ),
        allowed_tools=_normalize_string_list(
            allowed_tools,
            field_name="allowed_tools",
        ),
        permissions=list(permissions or []),
        request_id=normalized_request_id.strip(),
    )
