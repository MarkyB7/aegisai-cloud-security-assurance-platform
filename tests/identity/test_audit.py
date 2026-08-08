from src.identity.audit import build_authorization_audit_record
from src.identity.models import (
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationRequest,
    IdentityContext,
    Permission,
    ResourceContext,
    UserIdentity,
)


def test_builds_authorization_audit_record() -> None:
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
        session_id="session-123",
        request_id="request-123",
        allowed_models=["Claude"],
        allowed_tools=["KnowledgeBase"],
        permissions=[
            Permission(resource="KnowledgeBase", action="Read"),
        ],
    )

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
        ),
        context={
            "model": "Claude",
        },
    )

    decision = AuthorizationDecision(
        effect=AuthorizationEffect.ALLOW,
        reason="All applicable authorization policies were satisfied",
        policy_id="COMPOSITE_ENTERPRISE_POLICY",
        decision_id="decision-123",
        request_id="request-123",
    )

    record = build_authorization_audit_record(
        identity_context=identity,
        request=request,
        decision=decision,
    )

    assert record["event_type"] == "authorization_decision"
    assert record["request_id"] == "request-123"
    assert record["decision_id"] == "decision-123"
    assert record["principal"]["username"] == "alice"
    assert record["action"] == "Read"
    assert record["resource"]["resource_id"] == "finance-kb"
    assert record["decision"] == "ALLOW"
    assert record["policy_id"] == "COMPOSITE_ENTERPRISE_POLICY"
    assert record["reason"]
    assert record["event_id"]
    assert record["timestamp"]
