from datetime import datetime, timedelta, timezone

import pytest

from src.identity.access_governance import (
    Entitlement,
    ReviewDisposition,
)
from src.identity.access_review import perform_access_review


def entitlement(
    entitlement_id: str,
    permission: str,
    *,
    privileged: bool = False,
    last_used_days_ago: int = 10,
) -> Entitlement:
    now = datetime.now(timezone.utc)

    return Entitlement(
        entitlement_id=entitlement_id,
        resource_type="Application",
        resource_id="resource-1",
        permission=permission,
        environment="production",
        granted_at=now - timedelta(days=120),
        last_used_at=now - timedelta(days=last_used_days_ago),
        privileged=privileged,
    )


def test_safe_identity_is_kept() -> None:
    entitlements = [
        entitlement("ent-001", "ReadKnowledgeBase"),
        entitlement("ent-002", "InvokeModel"),
    ]

    review = perform_access_review(
        identity_id="alice",
        entitlements=entitlements,
    )

    assert review.overall_disposition is ReviewDisposition.KEEP
    assert review.overall_risk_score == 0
    assert review.sod_conflicts == ()


def test_stale_access_requires_review() -> None:
    entitlements = [
        entitlement(
            "ent-001",
            "ReadKnowledgeBase",
            last_used_days_ago=120,
        )
    ]

    review = perform_access_review(
        identity_id="alice",
        entitlements=entitlements,
    )

    assert review.overall_disposition is ReviewDisposition.REVIEW
    assert review.overall_risk_score == 50


def test_active_privileged_access_requires_review() -> None:
    entitlements = [
        entitlement(
            "ent-001",
            "AdministerModel",
            privileged=True,
        )
    ]

    review = perform_access_review(
        identity_id="alice",
        entitlements=entitlements,
    )

    assert review.overall_disposition is ReviewDisposition.REVIEW
    assert review.overall_risk_score == 70


def test_critical_sod_conflict_requires_removal() -> None:
    entitlements = [
        entitlement("ent-001", "CreateVendor"),
        entitlement("ent-002", "ApprovePayment"),
    ]

    review = perform_access_review(
        identity_id="alice",
        entitlements=entitlements,
    )

    assert review.overall_disposition is ReviewDisposition.REMOVE
    assert review.overall_risk_score == 100

    assert len(review.sod_conflicts) == 1
    assert (
        review.sod_conflicts[0].rule_id
        == "SOD-VENDOR-PAYMENT"
    )


def test_high_risk_model_conflict_requires_review() -> None:
    entitlements = [
        entitlement("ent-001", "ModifyModel"),
        entitlement(
            "ent-002",
            "ApproveModelDeployment",
        ),
    ]

    review = perform_access_review(
        identity_id="alice",
        entitlements=entitlements,
    )

    assert review.overall_disposition is ReviewDisposition.REVIEW
    assert review.overall_risk_score == 90


def test_rejects_empty_identity_id() -> None:
    with pytest.raises(
        ValueError,
        match="identity_id must be provided",
    ):
        perform_access_review(
            identity_id="   ",
            entitlements=[],
        )
