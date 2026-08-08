"""
AegisAI Identity Models

Defines the core enterprise identity objects used throughout the
AegisAI Cloud Security Assurance Platform.

Author: Mark Blas
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Mapping, Optional


@dataclass(slots=True)
class Permission:
    """
    Represents a single permission granted to a user.
    """

    resource: str
    action: str

class AuthorizationEffect(str, Enum):
    """
    Final authorization outcome.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(slots=True, frozen=True)
class ResourceContext:
    """
    Security attributes describing the resource being accessed.
    """

    resource_id: str
    resource_type: str
    classification: str
    owner_department: str
    environment: str = "production"


@dataclass(slots=True, frozen=True)
class AuthorizationRequest:
    """
    Complete authorization question submitted to the policy engine.

    Conceptually:
        Can PRINCIPAL perform ACTION on RESOURCE under CONTEXT?
    """

    action: str
    resource: ResourceContext
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class AuthorizationDecision:
    """
    Result returned by the authorization Policy Decision Point.
    """

    effect: AuthorizationEffect
    reason: str
    policy_id: str
    decision_id: str
    request_id: str
    evaluated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def allowed(self) -> bool:
        return self.effect is AuthorizationEffect.ALLOW


@dataclass(slots=True)
class UserIdentity:
    """
    Represents the authenticated user.
    """

    user_id: str
    username: str
    email: str

    department: str
    role: str
    clearance: str


@dataclass(slots=True)
class IdentityContext:
    """
    Complete security context passed throughout AegisAI.

    Every downstream component receives this object instead
    of parsing tokens or claims again.
    """

    identity: UserIdentity

    authenticated: bool
    authorized: bool

    session_id: str

    allowed_models: List[str] = field(default_factory=list)

    allowed_tools: List[str] = field(default_factory=list)

    permissions: List[Permission] = field(default_factory=list)

    request_id: Optional[str] = None

    created_at: datetime = field(
    default_factory=lambda: datetime.now(timezone.utc)
)


@dataclass(slots=True)
class AuditEvent:
    """
    Immutable authentication and authorization record.
    """

    event_id: str

    timestamp: datetime

    username: str

    action: str

    result: str

    source_ip: str

    user_agent: str

    request_id: str
