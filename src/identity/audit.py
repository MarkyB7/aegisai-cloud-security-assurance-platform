"""
Authorization decision evidence for the AegisAI identity subsystem.

This module converts authorization outcomes into structured audit records
that can later be sent to CloudWatch, S3, Security Hub, or a SIEM.
"""

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import (
    AuthorizationDecision,
    AuthorizationRequest,
    IdentityContext,
)


def build_authorization_audit_record(
    *,
    identity_context: IdentityContext,
    request: AuthorizationRequest,
    decision: AuthorizationDecision,
) -> dict[str, Any]:
    """
    Build a structured authorization decision record.

    The record is intentionally provider-neutral so it can later be
    serialized to JSON and forwarded to AWS logging/evidence services.
    """

    return {
        "event_id": str(uuid4()),
        "event_type": "authorization_decision",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": decision.request_id,
        "decision_id": decision.decision_id,
        "principal": {
            "user_id": identity_context.identity.user_id,
            "username": identity_context.identity.username,
            "department": identity_context.identity.department,
            "role": identity_context.identity.role,
            "clearance": identity_context.identity.clearance,
        },
        "action": request.action,
        "resource": {
            "resource_id": request.resource.resource_id,
            "resource_type": request.resource.resource_type,
            "classification": request.resource.classification,
            "owner_department": request.resource.owner_department,
            "environment": request.resource.environment,
        },
        "context": dict(request.context),
        "decision": decision.effect.value,
        "policy_id": decision.policy_id,
        "reason": decision.reason,
    }
