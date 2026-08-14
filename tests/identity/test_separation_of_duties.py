from datetime import datetime, timezone

from src.identity.access_governance import Entitlement
from src.identity.separation_of_duties import (
    detect_sod_conflicts,
)


def entitlement(
    entitlement_id: str,
    permission: str,
) -> Entitlement:
    now = datetime.now(timezone.utc)

    return Entitlement(
        entitlement_id=entitlement_id,
        resource_type="Application",
        resource_id="resource-1",
        permission=permission,
        environment="production",
        granted_at=now,
        last_used_at=now,
        privileged=False,
    )


def test_no_conflict_for_safe_permissions() -> None:
    entitlements = [
        entitlement("ent-001", "ReadKnowledgeBase"),
        entitlement("ent-002", "InvokeModel"),
    ]

    conflicts = detect_sod_conflicts(entitlements)

    assert conflicts == []


def test_detects_vendor_payment_conflict() -> None:
    entitlements = [
        entitlement("ent-001", "CreateVendor"),
        entitlement("ent-002", "ApprovePayment"),
    ]

    conflicts = detect_sod_conflicts(entitlements)

    assert len(conflicts) == 1
    assert conflicts[0].rule_id == "SOD-VENDOR-PAYMENT"
    assert conflicts[0].risk_score == 100
    assert conflicts[0].entitlement_ids == (
        "ent-001",
        "ent-002",
    )


def test_detects_model_deployment_conflict() -> None:
    entitlements = [
        entitlement("ent-001", "ModifyModel"),
        entitlement("ent-002", "ApproveModelDeployment"),
    ]

    conflicts = detect_sod_conflicts(entitlements)

    assert len(conflicts) == 1
    assert conflicts[0].rule_id == "SOD-MODEL-DEPLOYMENT"
    assert conflicts[0].risk_score == 90


def test_detects_security_policy_conflict() -> None:
    entitlements = [
        entitlement("ent-001", "ModifySecurityPolicy"),
        entitlement("ent-002", "ApproveSecurityPolicy"),
    ]

    conflicts = detect_sod_conflicts(entitlements)

    assert len(conflicts) == 1
    assert conflicts[0].rule_id == "SOD-SECURITY-POLICY"
    assert conflicts[0].risk_score == 100


def test_detects_multiple_simultaneous_conflicts() -> None:
    entitlements = [
        entitlement("ent-001", "CreateVendor"),
        entitlement("ent-002", "ApprovePayment"),
        entitlement("ent-003", "ModifyModel"),
        entitlement("ent-004", "ApproveModelDeployment"),
        entitlement("ent-005", "ModifySecurityPolicy"),
        entitlement("ent-006", "ApproveSecurityPolicy"),
    ]

    conflicts = detect_sod_conflicts(entitlements)

    assert len(conflicts) == 3

    rule_ids = {
        conflict.rule_id
        for conflict in conflicts
    }

    assert rule_ids == {
        "SOD-VENDOR-PAYMENT",
        "SOD-MODEL-DEPLOYMENT",
        "SOD-SECURITY-POLICY",
    }


def test_duplicate_entitlements_do_not_duplicate_conflict_ids() -> None:
    entitlements = [
        entitlement("ent-001", "CreateVendor"),
        entitlement("ent-001", "CreateVendor"),
        entitlement("ent-002", "ApprovePayment"),
    ]

    conflicts = detect_sod_conflicts(entitlements)

    assert len(conflicts) == 1
    assert conflicts[0].entitlement_ids == (
        "ent-001",
        "ent-002",
    )
