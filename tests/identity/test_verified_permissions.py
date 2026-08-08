"""
Unit tests for the Amazon Verified Permissions authorization adapter.

The tests use a mocked AWS client so the request translation and decision
handling can be verified without requiring live AWS infrastructure.
"""

from unittest.mock import Mock

import pytest

from src.identity.models import (
    AuthorizationEffect,
    AuthorizationRequest,
    IdentityContext,
    Permission,
    ResourceContext,
    UserIdentity,
)
from src.identity.verified_permissions import (
    VerifiedPermissionsAuthorizationService,
)


POLICY_STORE_ID = "ps-aegisai-test"


def build_identity_context(
    *,
    authenticated: bool = True,
    clearance: str = "Confidential",
    allowed_models: list[str] | None = None,
    allowed_tools: list[str] | None = None,
) -> IdentityContext:
    return IdentityContext(
        identity=UserIdentity(
            user_id="user-123",
            username="alice",
            email="alice@example.com",
            department="Finance",
            role="Financial Analyst",
            clearance=clearance,
        ),
        authenticated=authenticated,
        authorized=False,
        session_id="session-123",
        request_id="request-123",
        permissions=[
            Permission(
                resource="KnowledgeBase",
                action="Read",
            ),
        ],
        allowed_models=allowed_models or ["model-claude"],
        allowed_tools=allowed_tools or ["knowledge-base"],
    )


def build_service(
    *,
    decision: str = "ALLOW",
    determining_policies: list[dict[str, str]] | None = None,
) -> tuple[VerifiedPermissionsAuthorizationService, Mock]:
    client = Mock()

    client.is_authorized.return_value = {
        "decision": decision,
        "determiningPolicies": determining_policies or [],
        "errors": [],
    }

    service = VerifiedPermissionsAuthorizationService(
        policy_store_id=POLICY_STORE_ID,
        region_name="us-west-2",
        client=client,
    )

    return service, client


def test_translates_principal_correctly() -> None:
    service, client = build_service(
        determining_policies=[
            {"policyId": "policy-finance-read"},
        ],
    )

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    call = client.is_authorized.call_args.kwargs

    assert call["principal"] == {
        "entityType": "AegisAI::User",
        "entityId": "user-123",
    }


def test_maps_knowledge_base_action() -> None:
    service, client = build_service()

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

    service.authorize(
        identity_context=identity,
        request=request,
    )

    call = client.is_authorized.call_args.kwargs

    assert call["action"] == {
        "actionType": "AegisAI::Action",
        "actionId": "ReadKnowledgeBase",
    }


def test_maps_model_action() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Invoke",
        resource=ResourceContext(
            resource_id="model-claude",
            resource_type="Model",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    call = client.is_authorized.call_args.kwargs

    assert call["action"]["actionId"] == "InvokeModel"


def test_maps_tool_action() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Invoke",
        resource=ResourceContext(
            resource_id="knowledge-base",
            resource_type="Tool",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    call = client.is_authorized.call_args.kwargs

    assert call["action"]["actionId"] == "InvokeTool"


def test_builds_resource_entity() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    call = client.is_authorized.call_args.kwargs

    assert call["resource"] == {
        "entityType": "AegisAI::KnowledgeBase",
        "entityId": "finance-kb",
    }


def test_translates_principal_attributes() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    entities = client.is_authorized.call_args.kwargs["entities"]["entityList"]

    principal = entities[0]

    assert principal["attributes"]["department"] == {
        "string": "Finance"
    }

    assert principal["attributes"]["role"] == {
        "string": "Financial Analyst"
    }

    assert principal["attributes"]["clearanceLevel"] == {
        "long": 2
    }


def test_translates_resource_attributes() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Confidential",
            owner_department="Finance",
            environment="production",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    entities = client.is_authorized.call_args.kwargs["entities"]["entityList"]

    resource = entities[1]

    assert resource["attributes"]["ownerDepartment"] == {
        "string": "Finance"
    }

    assert resource["attributes"]["classificationLevel"] == {
        "long": 2
    }

    assert resource["attributes"]["environment"] == {
        "string": "production"
    }


def test_adds_model_id_attribute() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Invoke",
        resource=ResourceContext(
            resource_id="model-claude",
            resource_type="Model",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    entities = client.is_authorized.call_args.kwargs["entities"]["entityList"]

    resource = entities[1]

    assert resource["attributes"]["modelId"] == {
        "string": "model-claude"
    }


def test_adds_tool_id_attribute() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Invoke",
        resource=ResourceContext(
            resource_id="knowledge-base",
            resource_type="Tool",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    service.authorize(
        identity_context=identity,
        request=request,
    )

    entities = client.is_authorized.call_args.kwargs["entities"]["entityList"]

    resource = entities[1]

    assert resource["attributes"]["toolId"] == {
        "string": "knowledge-base"
    }


def test_converts_allow_decision() -> None:
    service, _ = build_service(
        decision="ALLOW",
        determining_policies=[
            {"policyId": "policy-123"},
        ],
    )

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

    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.allowed is True
    assert decision.policy_id == "policy-123"


def test_converts_explicit_deny_decision() -> None:
    service, _ = build_service(
        decision="DENY",
        determining_policies=[
            {"policyId": "policy-production-deny"},
        ],
    )

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

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.allowed is False
    assert decision.policy_id == "policy-production-deny"


def test_identifies_implicit_default_deny() -> None:
    service, _ = build_service(
        decision="DENY",
        determining_policies=[],
    )

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

    assert decision.effect is AuthorizationEffect.DENY

    assert (
        decision.policy_id
        == "VERIFIED_PERMISSIONS_DEFAULT_DENY"
    )


def test_does_not_call_aws_for_unauthenticated_principal() -> None:
    service, client = build_service()

    identity = build_identity_context(
        authenticated=False,
    )

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

    client.is_authorized.assert_not_called()


def test_unknown_principal_clearance_fails_closed() -> None:
    service, _ = build_service()

    identity = build_identity_context(
        clearance="UnknownClassification",
    )

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    with pytest.raises(
        ValueError,
        match="Unknown principal clearance",
    ):
        service.authorize(
            identity_context=identity,
            request=request,
        )


def test_unknown_resource_classification_fails_closed() -> None:
    service, _ = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Read",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="UnknownClassification",
            owner_department="Finance",
        ),
    )

    with pytest.raises(
        ValueError,
        match="Unknown resource classification",
    ):
        service.authorize(
            identity_context=identity,
            request=request,
        )


def test_unknown_action_mapping_fails_closed() -> None:
    service, client = build_service()

    identity = build_identity_context()

    request = AuthorizationRequest(
        action="Destroy",
        resource=ResourceContext(
            resource_id="finance-kb",
            resource_type="KnowledgeBase",
            classification="Internal",
            owner_department="Finance",
        ),
    )

    with pytest.raises(
        ValueError,
        match="No Cedar action mapping",
    ):
        service.authorize(
            identity_context=identity,
            request=request,
        )

    client.is_authorized.assert_not_called()
