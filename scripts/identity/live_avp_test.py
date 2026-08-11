"""
Live Amazon Verified Permissions integration test for AegisAI.

This script exercises the real AegisAI -> AVP -> Cedar authorization path.
"""

import os

from pathlib import Path

from src.identity.audit import build_authorization_audit_record
from src.identity.audit_sink import JsonLineAuditSink
from src.identity.models import (
    AuthorizationRequest,
    IdentityContext,
    ResourceContext,
    UserIdentity,
)
from src.identity.verified_permissions import (
    VerifiedPermissionsAuthorizationService,
)


POLICY_STORE_ID = os.environ.get("AEGISAI_POLICY_STORE_ID")

if not POLICY_STORE_ID:
    raise RuntimeError(
        "AEGISAI_POLICY_STORE_ID environment variable is not set"
    )


service = VerifiedPermissionsAuthorizationService(
    policy_store_id=POLICY_STORE_ID,
    region_name="us-west-2",
)

evidence_sink = JsonLineAuditSink(
    file_path=Path(
        "evidence/identity/live-authorization-decisions.jsonl"
    )
)

identity = IdentityContext(
    identity=UserIdentity(
        user_id="user-123",
        username="alice",
        email="alice@example.com",
        department="Finance",
        role="Financial Analyst",
        clearance="Confidential",
    ),
    authenticated=True,
    authorized=False,
    session_id="session-live-001",
    request_id="request-live-001",
    allowed_models=["model-claude"],
    allowed_tools=["knowledge-base"],
)


allow_request = AuthorizationRequest(
    action="Read",
    resource=ResourceContext(
        resource_id="finance-kb",
        resource_type="KnowledgeBase",
        classification="Confidential",
        owner_department="Finance",
        environment="production",
    ),
)


deny_request = AuthorizationRequest(
    action="Read",
    resource=ResourceContext(
        resource_id="hr-kb",
        resource_type="KnowledgeBase",
        classification="Confidential",
        owner_department="HR",
        environment="production",
    ),
)


print("\n=== EXPECTED ALLOW ===")

allow_decision = service.authorize(
    identity_context=identity,
    request=allow_request,
)

allow_record = build_authorization_audit_record(
    identity_context=identity,
    request=allow_request,
    decision=allow_decision,
)

evidence_sink.write(allow_record)

print(f"Decision:  {allow_decision.effect.value}")
print(f"Policy:    {allow_decision.policy_id}")
print(f"Reason:    {allow_decision.reason}")
print(f"Request:   {allow_decision.request_id}")
print(f"Decision:  {allow_decision.decision_id}")


print("\n=== EXPECTED DENY ===")

deny_decision = service.authorize(
    identity_context=identity,
    request=deny_request,
)

deny_record = build_authorization_audit_record(
    identity_context=identity,
    request=deny_request,
    decision=deny_decision,
)

evidence_sink.write(deny_record)

print(f"Decision:  {deny_decision.effect.value}")
print(f"Policy:    {deny_decision.policy_id}")
print(f"Reason:    {deny_decision.reason}")
print(f"Request:   {deny_decision.request_id}")
print(f"Decision:  {deny_decision.decision_id}")
