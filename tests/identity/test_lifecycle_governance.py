from datetime import datetime, timedelta, timezone

from src.identity.access_governance import (
    Entitlement,
    ReviewDisposition,
)
from src.identity.identity_lifecycle import (
    LifecycleEvent,
)
from src.identity.lifecycle_governance import (
    evaluate_lifecycle_change,
)


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


def test_safe_joiner_does_not_require_approval() -> None:
    target = [
        entitlement("BaseAccess", "ReadKnowledgeBase"),
        entitlement("FinanceRead", "ReadKnowledgeBase"),
    ]

    result = evaluate_lifecycle_change(
        identity_id="alice",
        event=LifecycleEvent.JOINER,
        current_entitlements=[],
        target_entitlements=target,
    )

    assert result.requires_approval is False
    assert result.access_review is not None
    assert (
        result.access_review.overall_disposition
        is ReviewDisposition.KEEP
    )


def test_safe_mover_does_not_require_approval() -> None:
    current = [
        entitlement("FinanceRead", "ReadKnowledgeBase"),
    ]

    target = [
        entitlement("SecurityRead", "ReadKnowledgeBase"),
    ]

    result = evaluate_lifecycle_change(
        identity_id="alice",
        event=LifecycleEvent.MOVER,
        current_entitlements=current,
        target_entitlements=target,
    )

    assert result.requires_approval is False
    assert result.lifecycle_plan.revoke_sessions is True


def test_privileged_mover_requires_approval() -> None:
    current = [
        entitlement("FinanceRead", "ReadKnowledgeBase"),
    ]

    target = [
        entitlement(
            "SecurityAdmin",
            "AdministerSecurity",
            privileged=True,
        ),
    ]

    result = evaluate_lifecycle_change(
        identity_id="alice",
        event=LifecycleEvent.MOVER,
        current_entitlements=current,
        target_entitlements=target,
    )

    assert result.requires_approval is True
    assert result.access_review is not None
    assert (
        result.access_review.overall_disposition
        is ReviewDisposition.REVIEW
    )


def test_sod_conflict_requires_approval() -> None:
    target = [
        entitlement("ent-001", "CreateVendor"),
        entitlement("ent-002", "ApprovePayment"),
    ]

    result = evaluate_lifecycle_change(
        identity_id="alice",
        event=LifecycleEvent.MOVER,
        current_entitlements=[],
        target_entitlements=target,
    )

    assert result.requires_approval is True
    assert result.access_review is not None
    assert result.access_review.sod_conflicts


def test_leaver_skips_access_review_and_revokes_access() -> None:
    current = [
        entitlement("FinanceRead", "ReadKnowledgeBase"),
        entitlement("ModelInvoke", "InvokeModel"),
    ]

    result = evaluate_lifecycle_change(
        identity_id="alice",
        event=LifecycleEvent.LEAVER,
        current_entitlements=current,
    )

    assert result.requires_approval is False
    assert result.access_review is None
    assert result.lifecycle_plan.disable_identity is True
    assert result.lifecycle_plan.revoke_sessions is True

    assert len(result.lifecycle_plan.changes) == 2
