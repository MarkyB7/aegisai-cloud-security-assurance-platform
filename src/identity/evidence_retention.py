"""
Evidence retention policy for AegisAI authorization records.

This module defines how long authorization evidence should be retained
and calculates expiration metadata for stored records.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


DEFAULT_RETENTION_DAYS = 365


def apply_retention_metadata(
    record: Mapping[str, Any],
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> dict[str, Any]:
    """
    Add retention metadata to an evidence record.

    The original record is not modified.
    """
    if retention_days <= 0:
        raise ValueError("retention_days must be greater than zero")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=retention_days)

    enriched_record = dict(record)

    enriched_record["retention"] = {
        "retention_days": retention_days,
        "retention_start": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }

    return enriched_record
