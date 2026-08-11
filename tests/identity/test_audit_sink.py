import json

from src.identity.audit_sink import JsonLineAuditSink


def test_writes_structured_jsonl_record(
    tmp_path,
) -> None:
    evidence_file = tmp_path / "authorization.jsonl"

    sink = JsonLineAuditSink(
        file_path=evidence_file,
    )

    record = {
        "event_type": "authorization_decision",
        "request_id": "request-123",
        "decision": "ALLOW",
        "policy_id": "policy-123",
    }

    sink.write(record)

    assert evidence_file.exists()

    stored_record = json.loads(
        evidence_file.read_text(
            encoding="utf-8"
        ).strip()
    )

    assert stored_record == record


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
