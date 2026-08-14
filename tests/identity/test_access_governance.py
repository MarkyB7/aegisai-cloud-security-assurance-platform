from datetime import datetime, timedelta, timezone

import pytest

from src.identity.access_governance import (
    Entitlement,
    ReviewDisposition,
    evaluate_entitlement,
)


def build_entitlement(
    *,
    entitlement_id: str = "entitlement-001",
    privileged: bool = False,
    last_used_days_ago: int | None = 10,
) -> Entitlement:
    now = datetime.now(timezone.utc)

    last_used_at = (
        now - timedelta(days=last_used_days_ago)
        if last_used_days_ago is not None
        else None
    )

    return Entitlement(
        entitlement_id=entitlement_id,
        resource_type="Tool",
        resource_id="finance-tool",
        permission="Invoke",
        environment="production",
        granted_at=now - timedelta(days=120),
        last_used_at=last_used_at,
        privileged=privileged,
    )


def test_keeps_recent_standard_entitlement() -> None:
    entitlement = build_entitlement(
        privileged=False,
        last_used_days_ago=10,
    )

    finding = evaluate_entitlement(entitlement)

    assert finding.disposition is ReviewDisposition.KEEP
    assert finding.risk_score == 0


def test_reviews_stale_standard_entitlement() -> None:
    entitlement = build_entitlement(
        privileged=False,
        last_used_days_ago=120,
    )

    finding = evaluate_entitlement(entitlement)

    assert finding.disposition is ReviewDisposition.REVIEW
    assert finding.risk_score == 50


def test_reviews_active_privileged_entitlement() -> None:
    entitlement = build_entitlement(
        privileged=True,
        last_used_days_ago=10,
    )

    finding = evaluate_entitlement(entitlement)

    assert finding.disposition is ReviewDisposition.REVIEW
    assert finding.risk_score == 70


def test_removes_stale_privileged_entitlement() -> None:
    entitlement = build_entitlement(
        privileged=True,
        last_used_days_ago=120,
    )

    finding = evaluate_entitlement(entitlement)

    assert finding.disposition is ReviewDisposition.REMOVE
    assert finding.risk_score == 100


def test_never_used_entitlement_uses_grant_date() -> None:
    entitlement = build_entitlement(
        privileged=False,
        last_used_days_ago=None,
    )

    finding = evaluate_entitlement(entitlement)

    assert finding.disposition is ReviewDisposition.REVIEW
    assert finding.risk_score == 50


def test_rejects_invalid_stale_threshold() -> None:
    entitlement = build_entitlement()

    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        evaluate_entitlement(
            entitlement,
            stale_after_days=0,
        )
