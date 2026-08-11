from src.identity.evidence_integrity import (
    calculate_record_digest,
    verify_record_digest,
)


def test_digest_is_deterministic() -> None:
    record_a = {
        "decision": "ALLOW",
        "request_id": "request-123",
        "policy_id": "policy-123",
    }

    record_b = {
        "policy_id": "policy-123",
        "request_id": "request-123",
        "decision": "ALLOW",
    }

    digest_a = calculate_record_digest(record_a)
    digest_b = calculate_record_digest(record_b)

    assert digest_a == digest_b


def test_detects_tampered_record() -> None:
    record = {
        "decision": "DENY",
        "request_id": "request-123",
        "policy_id": "policy-123",
    }

    digest = calculate_record_digest(record)

    record["decision"] = "ALLOW"

    assert verify_record_digest(
        record,
        digest,
    ) is False


def test_verifies_unchanged_record() -> None:
    record = {
        "decision": "ALLOW",
        "request_id": "request-123",
    }

    digest = calculate_record_digest(record)

    assert verify_record_digest(
        record,
        digest,
    ) is True
