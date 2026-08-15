"""
Identity lifecycle governance for AegisAI.

This module models Joiner-Mover-Leaver (JML) lifecycle events and
determines the access changes required when an identity joins,
changes roles, or leaves the organization.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class LifecycleEvent(str, Enum):
    JOINER = "JOINER"
    MOVER = "MOVER"
    LEAVER = "LEAVER"


class AccessChangeAction(str, Enum):
    GRANT = "GRANT"
    REVOKE = "REVOKE"


@dataclass(frozen=True)
class RoleEntitlement:
    entitlement_id: str
    role: str


@dataclass(frozen=True)
class AccessChange:
    entitlement_id: str
    action: AccessChangeAction
    reason: str


@dataclass(frozen=True)
class LifecyclePlan:
    identity_id: str
    event: LifecycleEvent
    changes: tuple[AccessChange, ...]
    disable_identity: bool
    revoke_sessions: bool


def build_lifecycle_plan(
    *,
    identity_id: str,
    event: LifecycleEvent,
    current_entitlements: Iterable[str] = (),
    target_entitlements: Iterable[str] = (),
) -> LifecyclePlan:
    """
    Calculate required access changes for a JML lifecycle event.
    """
    if not identity_id.strip():
        raise ValueError("identity_id must be provided")

    current = set(current_entitlements)
    target = set(target_entitlements)

    changes: list[AccessChange] = []

    if event is LifecycleEvent.JOINER:
        for entitlement_id in sorted(target - current):
            changes.append(
                AccessChange(
                    entitlement_id=entitlement_id,
                    action=AccessChangeAction.GRANT,
                    reason="Required access for new identity",
                )
            )

        return LifecyclePlan(
            identity_id=identity_id,
            event=event,
            changes=tuple(changes),
            disable_identity=False,
            revoke_sessions=False,
        )

    if event is LifecycleEvent.MOVER:
        for entitlement_id in sorted(current - target):
            changes.append(
                AccessChange(
                    entitlement_id=entitlement_id,
                    action=AccessChangeAction.REVOKE,
                    reason=(
                        "Access no longer required after role change"
                    ),
                )
            )

        for entitlement_id in sorted(target - current):
            changes.append(
                AccessChange(
                    entitlement_id=entitlement_id,
                    action=AccessChangeAction.GRANT,
                    reason="Access required for new role",
                )
            )

        return LifecyclePlan(
            identity_id=identity_id,
            event=event,
            changes=tuple(changes),
            disable_identity=False,
            revoke_sessions=True,
        )

    if event is LifecycleEvent.LEAVER:
        for entitlement_id in sorted(current):
            changes.append(
                AccessChange(
                    entitlement_id=entitlement_id,
                    action=AccessChangeAction.REVOKE,
                    reason="Identity has left the organization",
                )
            )

        return LifecyclePlan(
            identity_id=identity_id,
            event=event,
            changes=tuple(changes),
            disable_identity=True,
            revoke_sessions=True,
        )

    raise ValueError(
        f"Unsupported lifecycle event: {event}"
    )
