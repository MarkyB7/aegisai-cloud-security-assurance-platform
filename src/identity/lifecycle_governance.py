"""
Lifecycle governance orchestration for AegisAI.

This module combines Joiner-Mover-Leaver lifecycle planning with
identity access governance.
"""

from dataclasses import dataclass
from typing import Iterable

from .access_governance import (
    Entitlement,
    ReviewDisposition,
)
from .access_review import (
    IdentityAccessReview,
    perform_access_review,
)
from .identity_lifecycle import (
    LifecycleEvent,
    LifecyclePlan,
    build_lifecycle_plan,
)


@dataclass(frozen=True)
class LifecycleGovernanceResult:
    identity_id: str
    lifecycle_plan: LifecyclePlan
    access_review: IdentityAccessReview | None
    requires_approval: bool


def evaluate_lifecycle_change(
    *,
    identity_id: str,
    event: LifecycleEvent,
    current_entitlements: Iterable[Entitlement],
    target_entitlements: Iterable[Entitlement] = (),
) -> LifecycleGovernanceResult:
    """
    Build a lifecycle plan and evaluate the resulting access posture.
    """
    current = list(current_entitlements)
    target = list(target_entitlements)

    lifecycle_plan = build_lifecycle_plan(
        identity_id=identity_id,
        event=event,
        current_entitlements=[
            entitlement.entitlement_id
            for entitlement in current
        ],
        target_entitlements=[
            entitlement.entitlement_id
            for entitlement in target
        ],
    )

    if event is LifecycleEvent.LEAVER:
        return LifecycleGovernanceResult(
            identity_id=identity_id,
            lifecycle_plan=lifecycle_plan,
            access_review=None,
            requires_approval=False,
        )

    access_review = perform_access_review(
        identity_id=identity_id,
        entitlements=target,
    )

    requires_approval = (
        access_review.overall_disposition
        is not ReviewDisposition.KEEP
    )

    return LifecycleGovernanceResult(
        identity_id=identity_id,
        lifecycle_plan=lifecycle_plan,
        access_review=access_review,
        requires_approval=requires_approval,
    )
