"""
Identity governance and entitlement review for AegisAI.

This module evaluates user entitlements for excessive, stale,
inappropriate, or conflicting access.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class ReviewDisposition(str, Enum):
    KEEP = "KEEP"
    REMOVE = "REMOVE"
    REVIEW = "REVIEW"


@dataclass(frozen=True)
class Entitlement:
    entitlement_id: str
    resource_type: str
    resource_id: str
    permission: str
    environment: str
    granted_at: datetime
    last_used_at: datetime | None = None
    privileged: bool = False


@dataclass(frozen=True)
class AccessReviewFinding:
    entitlement_id: str
    disposition: ReviewDisposition
    reason: str
    risk_score: int


def evaluate_entitlement(
    entitlement: Entitlement,
    *,
    stale_after_days: int = 90,
) -> AccessReviewFinding:
    """
    Evaluate an entitlement for access-review risk.
    """
    if stale_after_days <= 0:
        raise ValueError(
            "stale_after_days must be greater than zero"
        )

    now = datetime.now(timezone.utc)

    reference_time = (
        entitlement.last_used_at
        or entitlement.granted_at
    )

    age_days = (
        now - reference_time
    ).days

    if entitlement.privileged and age_days >= stale_after_days:
        return AccessReviewFinding(
            entitlement_id=entitlement.entitlement_id,
            disposition=ReviewDisposition.REMOVE,
            reason="Privileged entitlement is stale",
            risk_score=100,
        )

    if entitlement.privileged:
        return AccessReviewFinding(
            entitlement_id=entitlement.entitlement_id,
            disposition=ReviewDisposition.REVIEW,
            reason="Privileged entitlement requires review",
            risk_score=70,
        )

    if age_days >= stale_after_days:
        return AccessReviewFinding(
            entitlement_id=entitlement.entitlement_id,
            disposition=ReviewDisposition.REVIEW,
            reason="Entitlement has not been used recently",
            risk_score=50,
        )

    return AccessReviewFinding(
        entitlement_id=entitlement.entitlement_id,
        disposition=ReviewDisposition.KEEP,
        reason="Entitlement remains active and appropriate",
        risk_score=0,
    )
