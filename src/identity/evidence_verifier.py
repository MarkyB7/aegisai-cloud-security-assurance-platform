"""
Stored evidence verification for AegisAI.

This module verifies that persisted authorization evidence has not been
modified after its integrity digest was generated.
"""

from copy import deepcopy
from typing import Any, Mapping

from .evidence_integrity import verify_record_digest


def verify_stored_evidence(
    evidence_record: Mapping[str, Any],
) -> bool:
    """
    Verify the SHA-256 integrity metadata attached to a stored record.
    """
    integrity = evidence_record.get("integrity")

    if not isinstance(integrity, Mapping):
        return False

    if integrity.get("algorithm") != "SHA-256":
        return False

    expected_digest = integrity.get("digest")

    if not isinstance(expected_digest, str) or not expected_digest:
        return False

    record_without_integrity = deepcopy(
        dict(evidence_record)
    )

    record_without_integrity.pop(
        "integrity",
        None,
    )

    return verify_record_digest(
        record_without_integrity,
        expected_digest,
    )
