"""
Evidence integrity helpers for AegisAI authorization records.

This module creates and verifies SHA-256 digests for sanitized
authorization evidence.
"""

import hashlib
import json
from typing import Any, Mapping


def canonicalize_record(
    record: Mapping[str, Any],
) -> bytes:
    """
    Convert a record into deterministic canonical JSON bytes.
    """
    canonical_json = json.dumps(
        dict(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return canonical_json.encode("utf-8")


def calculate_record_digest(
    record: Mapping[str, Any],
) -> str:
    """
    Return the SHA-256 digest for an evidence record.
    """
    return hashlib.sha256(
        canonicalize_record(record)
    ).hexdigest()


def verify_record_digest(
    record: Mapping[str, Any],
    expected_digest: str,
) -> bool:
    """
    Verify that a record still matches its expected SHA-256 digest.
    """
    actual_digest = calculate_record_digest(record)

    return actual_digest == expected_digest
