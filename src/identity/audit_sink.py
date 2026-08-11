"""
Audit evidence storage for the AegisAI identity subsystem.

The local JSONL sink provides a development evidence target.
Production implementations can later forward the same records to
Amazon S3, CloudWatch Logs, or an enterprise SIEM.
"""

import json
from pathlib import Path
from typing import Any, Mapping
from .evidence_policy import sanitize_authorization_record
from .evidence_integrity import calculate_record_digest

class JsonLineAuditSink:
    """
    Append structured authorization evidence as JSON Lines.
    """

    def __init__(self, *, file_path: str | Path) -> None:
        self._file_path = Path(file_path)

    def write(
        self,
        record: Mapping[str, Any],
    ) -> None:
        """
        Persist one audit record.

        Each line contains one complete JSON object.
        """
        self._file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        sanitized_record = sanitize_authorization_record(record)

        digest = calculate_record_digest(
            sanitized_record
        )

        evidence_record = {
            **sanitized_record,
            "integrity": {
                "algorithm": "SHA-256",
                "digest": digest,
            },
        }

        with self._file_path.open(
            "a",
            encoding="utf-8",
        ) as audit_file:

            json.dump(
                sanitized_record,
                audit_file,
                separators=(",", ":"),
                sort_keys=True,
            )

            audit_file.write("\n")
