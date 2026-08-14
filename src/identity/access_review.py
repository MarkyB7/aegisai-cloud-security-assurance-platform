"""
Enterprise access-review orchestration for AegisAI.

This service combines entitlement governance and Separation-of-Duties
analysis into a unified identity access review.
"""

from dataclasses import dataclass
from typing import Iterable

from .access_governance import (
    AccessReviewFinding,
    Entitlement,
    ReviewDisposition,
    evaluate_entitlement,
)
from .separation_of_duties import (
    SoDConflict,
    detect_sod_conflicts,
)


@dataclass(frozen=True)
class IdentityAccessReview:
    identity_id: str
    entitlement_findings: tuple[AccessReviewFinding, ...]
    sod_conflicts: tuple[SoDConflict, ...]
    overall_disposition: ReviewDisposition
    overall_risk_score: int


def perform_access_review(
    *,
    identity_id: str,
    entitlements: Iterable[Entitlement],
    stale_after_days: int = 90,
) -> IdentityAccessReview:
    """
    Perform a complete access review for one identity.
    """
    if not identity_id.strip():
        raise ValueError("identity_id must be provided")

    entitlement_list = list(entitlements)

    findings = tuple(
        evaluate_entitlement(
            entitlement,
            stale_after_days=stale_after_days,
        )
        for entitlement in entitlement_list
    )

    sod_conflicts = tuple(
        detect_sod_conflicts(entitlement_list)
    )

    risk_scores = [
        finding.risk_score
        for finding in findings
    ]

    risk_scores.extend(
        conflict.risk_score
        for conflict in sod_conflicts
    )

    overall_risk_score = max(
        risk_scores,
        default=0,
    )

    if (
        any(
            finding.disposition is ReviewDisposition.REMOVE
            for finding in findings
        )
        or any(
            conflict.risk_score >= 100
            for conflict in sod_conflicts
        )
    ):
        overall_disposition = ReviewDisposition.REMOVE

    elif (
        any(
            finding.disposition is ReviewDisposition.REVIEW
            for finding in findings
        )
        or sod_conflicts
    ):
        overall_disposition = ReviewDisposition.REVIEW

    else:
        overall_disposition = ReviewDisposition.KEEP

    return IdentityAccessReview(
        identity_id=identity_id,
        entitlement_findings=findings,
        sod_conflicts=sod_conflicts,
        overall_disposition=overall_disposition,
        overall_risk_score=overall_risk_score,
    )
