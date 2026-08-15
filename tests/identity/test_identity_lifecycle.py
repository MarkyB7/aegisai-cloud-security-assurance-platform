from src.identity.identity_lifecycle import (
    AccessChangeAction,
    LifecycleEvent,
    build_lifecycle_plan,
)


def test_joiner_grants_required_access() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.JOINER,
        current_entitlements=[],
        target_entitlements=[
            "FinanceRead",
            "FinanceReports",
        ],
    )

    assert plan.disable_identity is False
    assert plan.revoke_sessions is False
    assert len(plan.changes) == 2

    assert all(
        change.action is AccessChangeAction.GRANT
        for change in plan.changes
    )


def test_mover_revokes_old_and_grants_new_access() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.MOVER,
        current_entitlements=[
            "FinanceRead",
            "FinanceReports",
        ],
        target_entitlements=[
            "SecurityRead",
            "IncidentResponse",
        ],
    )

    revoked = {
        change.entitlement_id
        for change in plan.changes
        if change.action is AccessChangeAction.REVOKE
    }

    granted = {
        change.entitlement_id
        for change in plan.changes
        if change.action is AccessChangeAction.GRANT
    }

    assert revoked == {
        "FinanceRead",
        "FinanceReports",
    }

    assert granted == {
        "SecurityRead",
        "IncidentResponse",
    }

    assert plan.revoke_sessions is True
    assert plan.disable_identity is False


def test_mover_keeps_shared_entitlements() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.MOVER,
        current_entitlements=[
            "BaseAccess",
            "FinanceRead",
        ],
        target_entitlements=[
            "BaseAccess",
            "SecurityRead",
        ],
    )

    changed_ids = {
        change.entitlement_id
        for change in plan.changes
    }

    assert "BaseAccess" not in changed_ids
    assert "FinanceRead" in changed_ids
    assert "SecurityRead" in changed_ids


def test_leaver_revokes_all_access() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.LEAVER,
        current_entitlements=[
            "FinanceRead",
            "FinanceReports",
            "ModelInvoke",
        ],
    )

    assert plan.disable_identity is True
    assert plan.revoke_sessions is True

    assert len(plan.changes) == 3

    assert all(
        change.action is AccessChangeAction.REVOKE
        for change in plan.changes
    )


def test_joiner_does_not_duplicate_existing_access() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.JOINER,
        current_entitlements=[
            "BaseAccess",
        ],
        target_entitlements=[
            "BaseAccess",
            "FinanceRead",
        ],
    )

    assert len(plan.changes) == 1

    assert plan.changes[0].entitlement_id == "FinanceRead"
    assert (
        plan.changes[0].action
        is AccessChangeAction.GRANT
    )


def test_mover_with_identical_access_requires_no_changes() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.MOVER,
        current_entitlements=[
            "BaseAccess",
            "FinanceRead",
        ],
        target_entitlements=[
            "BaseAccess",
            "FinanceRead",
        ],
    )

    assert plan.changes == ()
    assert plan.revoke_sessions is True


def test_leaver_with_no_access_still_disables_identity() -> None:
    plan = build_lifecycle_plan(
        identity_id="alice",
        event=LifecycleEvent.LEAVER,
        current_entitlements=[],
    )

    assert plan.changes == ()
    assert plan.disable_identity is True
    assert plan.revoke_sessions is True
