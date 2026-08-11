"""
Evidence policy for the AegisAI identity subsystem.

This module applies data-minimization and sanitization rules before
authorization evidence is persisted.
"""

from copy import deepcopy
from typing import Any, Mapping


_SENSITIVE_PRINCIPAL_FIELDS = {
    "email",
}

_ALLOWED_PRINCIPAL_FIELDS = {
    "user_id",
    "username",
    "department",
    "role",
    "clearance",
}


def sanitize_authorization_record(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Return a sanitized copy of an authorization audit record.

    The original record is never modified.
    """
    sanitized = deepcopy(dict(record))

    principal = sanitized.get("principal")

    if isinstance(principal, dict):
        sanitized["principal"] = {
            key: value
            for key, value in principal.items()
            if key in _ALLOWED_PRINCIPAL_FIELDS
            and key not in _SENSITIVE_PRINCIPAL_FIELDS
        }

    context = sanitized.get("context")

    if isinstance(context, dict):
        sanitized["context"] = {
            key: value
            for key, value in context.items()
            if key not in {
                "authorization",
                "token",
                "access_token",
                "id_token",
                "secret",
                "password",
            }
        }

    return sanitized
