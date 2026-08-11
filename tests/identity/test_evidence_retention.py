import pytest

from src.identity.evidence_retention import (
    apply_retention_metadata,
)


def test_adds_retention_metadata() -> None:
    record = {
        "decision": "ALLOW",
        "request_id": "request-123",
    }

    enriched = apply_retention_metadata(
        record,
        retention_days=365,
    )

    assert enriched["retention"]["retention_days"] == 365
    assert enriched["retention"]["retention_start"]
    assert enriched["retention"]["expires_at"]


def test_does_not_modify_original_record() -> None:
    record = {
        "decision": "ALLOW",
    }

    apply_retention_metadata(record)

    assert "retention" not in record


def test_rejects_invalid_retention_period() -> None:
    record = {
        "decision": "ALLOW",
    }

    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        apply_retention_metadata(
            record,
            retention_days=0,
        )
