"""
Audit evidence storage for the AegisAI identity subsystem.

The local JSONL sink applies evidence policy, retention metadata,
and integrity protection before persisting authorization records.

Production implementations can later forward the same records to
Amazon S3, CloudWatch Logs, or an enterprise SIEM.
"""

import json
from pathlib import Path
from typing import Any, Mapping

from .evidence_integrity import calculate_record_digest
from .evidence_policy import sanitize_authorization_record
from .evidence_retention import (
    DEFAULT_RETENTION_DAYS,
    apply_retention_metadata,
)


class JsonLineAuditSink:
    """
    Append governed authorization evidence as JSON Lines.
    """

    def __init__(
        self,
        *,
        file_path: str | Path,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        if retention_days <= 0:
            raise ValueError(
                "retention_days must be greater than zero"
            )

        self._file_path = Path(file_path)
        self._retention_days = retention_days

    def write(
        self,
        record: Mapping[str, Any],
    ) -> None:
        """
        Sanitize, govern, integrity-protect, and persist one audit record.
        """
        sanitized_record = sanitize_authorization_record(
            record
        )

        retained_record = apply_retention_metadata(
            sanitized_record,
            retention_days=self._retention_days,
        )

        digest = calculate_record_digest(
            retained_record
        )

        evidence_record = {
            **retained_record,
            "integrity": {
                "algorithm": "SHA-256",
                "digest": digest,
            },
        }

        self._file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._file_path.open(
            "a",
            encoding="utf-8",
        ) as audit_file:
            json.dump(
                evidence_record,
                audit_file,
                separators=(",", ":"),
                sort_keys=True,
            )

            audit_file.write("\n")
