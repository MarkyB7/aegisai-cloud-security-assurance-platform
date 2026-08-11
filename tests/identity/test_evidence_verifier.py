from src.identity.evidence_integrity import (
    calculate_record_digest,
)
from src.identity.evidence_verifier import (
    verify_stored_evidence,
)


def build_evidence_record() -> dict:
    record = {
        "decision": "ALLOW",
        "request_id": "request-123",
        "policy_id": "policy-123",
    }

    digest = calculate_record_digest(record)

    return {
        **record,
        "integrity": {
            "algorithm": "SHA-256",
            "digest": digest,
        },
    }


def test_verifies_valid_stored_record() -> None:
    evidence = build_evidence_record()

    assert verify_stored_evidence(evidence) is True


def test_detects_modified_stored_record() -> None:
    evidence = build_evidence_record()

    evidence["decision"] = "DENY"

    assert verify_stored_evidence(evidence) is False


def test_rejects_missing_integrity_metadata() -> None:
    evidence = {
        "decision": "ALLOW",
    }

    assert verify_stored_evidence(evidence) is False


def test_rejects_unknown_integrity_algorithm() -> None:
    evidence = build_evidence_record()

    evidence["integrity"]["algorithm"] = "MD5"

    assert verify_stored_evidence(evidence) is False
