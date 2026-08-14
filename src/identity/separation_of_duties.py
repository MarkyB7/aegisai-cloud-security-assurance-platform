"""
Separation-of-Duties controls for AegisAI identity governance.

This module detects combinations of entitlements that create
unacceptable business or security risk when held by one identity.
"""

from dataclasses import dataclass
from typing import Iterable

from .access_governance import Entitlement


@dataclass(frozen=True)
class SoDRule:
    rule_id: str
    description: str
    first_permission: str
    second_permission: str
    risk_score: int


@dataclass(frozen=True)
class SoDConflict:
    rule_id: str
    description: str
    entitlement_ids: tuple[str, ...]
    risk_score: int


DEFAULT_SOD_RULES = (
    SoDRule(
        rule_id="SOD-VENDOR-PAYMENT",
        description=(
            "Identity cannot both create vendors "
            "and approve payments"
        ),
        first_permission="CreateVendor",
        second_permission="ApprovePayment",
        risk_score=100,
    ),
    SoDRule(
        rule_id="SOD-MODEL-DEPLOYMENT",
        description=(
            "Identity cannot both modify AI models "
            "and approve model deployment"
        ),
        first_permission="ModifyModel",
        second_permission="ApproveModelDeployment",
        risk_score=90,
    ),
    SoDRule(
        rule_id="SOD-SECURITY-POLICY",
        description=(
            "Identity cannot both modify security policy "
            "and approve security policy"
        ),
        first_permission="ModifySecurityPolicy",
        second_permission="ApproveSecurityPolicy",
        risk_score=100,
    ),
)


def detect_sod_conflicts(
    entitlements: Iterable[Entitlement],
    *,
    rules: Iterable[SoDRule] = DEFAULT_SOD_RULES,
) -> list[SoDConflict]:
    """
    Detect Separation-of-Duties conflicts across entitlements.
    """
    entitlement_list = list(entitlements)
    conflicts: list[SoDConflict] = []

    for rule in rules:
        first_matches = [
            entitlement
            for entitlement in entitlement_list
            if entitlement.permission == rule.first_permission
        ]

        second_matches = [
            entitlement
            for entitlement in entitlement_list
            if entitlement.permission == rule.second_permission
        ]

        if first_matches and second_matches:
            conflicting_ids = tuple(
                sorted(
                    {
                        entitlement.entitlement_id
                        for entitlement in (
                            first_matches + second_matches
                        )
                    }
                )
            )

            conflicts.append(
                SoDConflict(
                    rule_id=rule.rule_id,
                    description=rule.description,
                    entitlement_ids=conflicting_ids,
                    risk_score=rule.risk_score,
                )
            )

    return conflicts
