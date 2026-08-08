"""
Security tests for the AegisAI enterprise authorization subsystem.

These tests verify least privilege, attribute-based controls,
resource boundaries, AI model/tool restrictions, production controls,
default-deny behavior, and policy enforcement.
"""

import pytest

from src.identity.authorization import (
    AuthorizationService,
    enforce_authorization,
)
from src.identity.exceptions import AuthorizationError
from src.identity.models import (
    AuthorizationEffect,
    AuthorizationRequest,
    IdentityContext,
    Permission,
    ResourceContext,
    UserIdentity,
)


def build_identity_context(
    *,
    authenticated: bool = True,
    department: str = "Finance",
    role: str = "Financial Analyst",
    clearance: str = "Confidential",
    permissions: list[Permission] | None = None,
    allowed_models: list[str] | None = None,
    allowed_tools: list[str] | None = None,
) -> IdentityContext:
    """Create a controlled identity context for authorization tests."""

    if permissions is None:
        permissions = [
            Permission(resource="KnowledgeBase", action="Read"),
            Permission(resource="Model", action="Invoke"),
        ]

    if allowed_models is None:
        allowed_models = ["Claude"]

    if allowed_tools is None:
        allowed_tools = ["KnowledgeBase"]

    return IdentityContext(
        identity=UserIdentity(
            user_id="user-123",
            username="alice",
            email="alice@example.com",
            department=department,
            role=role,
            clearance=clearance,
        ),
        authenticated=authenticated,
        authorized=False,
        session_id="session-123",
        request_id="request-123",
        permissions=permissions,
        allowed_models=allowed_models,
        allowed_tools=allowed_tools,
    )


@pytest.fixture
def service() -> AuthorizationService:
    return AuthorizationService()


def test_allows_valid_authorized_request(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

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
            "tool": "KnowledgeBase",
        },
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.allowed is True
    assert decision.policy_id == "COMPOSITE_ENTERPRISE_POLICY"
    assert decision.request_id == "request-123"
    assert decision.decision_id


def test_denies_unauthenticated_identity(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context(authenticated=False)

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "AUTHN_REQUIRED"


def test_denies_missing_explicit_permission(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Delete",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "LEAST_PRIVILEGE"


def test_denies_cross_department_access(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="hr-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="HR",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "DEPARTMENT_BOUNDARY"


def test_denies_insufficient_clearance(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context(clearance="Internal")

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-confidential",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "DATA_CLASSIFICATION"


def test_denies_unapproved_model(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Invoke",
        resource=ResourceContext(
            resource_id="enterprise-model",
            resource_type="Model",
            classification="Internal",
            owner_department="Finance",
        ),
        context={"model": "UnapprovedModel"},
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "MODEL_ALLOWLIST"


def test_denies_unapproved_tool(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
        ),
        context={"tool": "PayrollExport"},
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "TOOL_ALLOWLIST"


def test_denies_intern_production_access(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context(role="Intern")

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
            environment="production",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "PRODUCTION_ACCESS"


def test_unknown_classification_fails_closed(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="unknown-data",
            resource_type="KnowledgeBase",
            classification="TopSecret",
            owner_department="Finance",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.policy_id == "DATA_CLASSIFICATION"


def test_enforcement_allows_permitted_decision(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    enforce_authorization(decision)


def test_enforcement_blocks_denied_decision(
    service: AuthorizationService,
) -> None:
    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Delete",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    decision = service.authorize(
        identity_context=identity,
        request=request,
    )

    with pytest.raises(AuthorizationError, match="LEAST_PRIVILEGE"):
        enforce_authorization(decision)
