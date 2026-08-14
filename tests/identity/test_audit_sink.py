import json

import pytest

from src.identity.audit_sink import JsonLineAuditSink
from src.identity.evidence_verifier import (
    verify_stored_evidence,
)


def test_writes_governed_jsonl_record(
    tmp_path,
) -> None:
    evidence_file = tmp_path / "authorization.jsonl"

    sink = JsonLineAuditSink(
        file_path=evidence_file,
        retention_days=365,
    )

    record = {
        "event_type": "authorization_decision",
        "request_id": "request-123",
        "decision": "ALLOW",
        "policy_id": "policy-123",
        "principal": {
            "user_id": "user-123",
            "username": "alice",
            "email": "alice@example.com",
        },
        "context": {
            "model": "Claude",
            "token": "do-not-store",
        },
    }

    sink.write(record)

    stored_record = json.loads(
        evidence_file.read_text(
            encoding="utf-8"
        ).strip()
    )

    assert stored_record["decision"] == "ALLOW"

    assert "email" not in stored_record["principal"]
    assert "token" not in stored_record["context"]

    assert stored_record["retention"]["retention_days"] == 365

    assert stored_record["integrity"]["algorithm"] == "SHA-256"
    assert stored_record["integrity"]["digest"]

    assert verify_stored_evidence(
        stored_record
    ) is True


def test_detects_tampering_after_storage(
    tmp_path,
) -> None:
    evidence_file = tmp_path / "authorization.jsonl"

    sink = JsonLineAuditSink(
        file_path=evidence_file,
    )

    sink.write(
        {
            "decision": "DENY",
            "request_id": "request-123",
        }
    )

    stored_record = json.loads(
        evidence_file.read_text(
            encoding="utf-8"
        ).strip()
    )

    stored_record["decision"] = "ALLOW"

    assert verify_stored_evidence(
        stored_record
    ) is False


def test_appends_multiple_records(
    tmp_path,
) -> None:
    evidence_file = tmp_path / "authorization.jsonl"

    sink = JsonLineAuditSink(
        file_path=evidence_file,
    )

    sink.write(
        {
            "decision": "ALLOW",
            "request_id": "request-1",
        }
    )

    sink.write(
        {
            "decision": "DENY",
            "request_id": "request-2",
        }
    )

    lines = evidence_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["decision"] == "ALLOW"
    assert second["decision"] == "DENY"


def test_rejects_invalid_retention_days(
    tmp_path,
) -> None:
    evidence_file = tmp_path / "authorization.jsonl"

    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        JsonLineAuditSink(
            file_path=evidence_file,
            retention_days=0,
        )
