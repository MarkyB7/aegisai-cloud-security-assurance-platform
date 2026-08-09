"""
Amazon Verified Permissions adapter for AegisAI.

This module translates AegisAI authorization requests into Amazon
Verified Permissions requests and converts AWS decisions back into the
provider-neutral AuthorizationDecision model.
"""

from typing import Any
from uuid import uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import (
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationRequest,
    IdentityContext,
)


_CLEARANCE_LEVELS = {
    "Public": 0,
    "Internal": 1,
    "Confidential": 2,
    "Restricted": 3,
}


class VerifiedPermissionsAuthorizationService:
    """
    Amazon Verified Permissions implementation of the AegisAI PDP.
    """

    def __init__(
        self,
        *,
        policy_store_id: str,
        region_name: str,
        client: Any | None = None,
    ) -> None:
        if not isinstance(policy_store_id, str) or not policy_store_id.strip():
            raise ValueError("policy_store_id must be provided")

        if not isinstance(region_name, str) or not region_name.strip():
            raise ValueError("region_name must be provided")

        self._policy_store_id = policy_store_id.strip()

        self._client = client or boto3.client(
            "verifiedpermissions",
            region_name=region_name.strip(),
        )

    def authorize(
        self,
        *,
        identity_context: IdentityContext,
        request: AuthorizationRequest,
    ) -> AuthorizationDecision:
        """
        Evaluate an authorization request through Amazon Verified Permissions.
        """
        request_id = identity_context.request_id or str(uuid4())

        if not identity_context.authenticated:
            return AuthorizationDecision(
                effect=AuthorizationEffect.DENY,
                reason="Principal is not authenticated",
                policy_id="AUTHN_REQUIRED",
                decision_id=str(uuid4()),
                request_id=request_id,
            )

        try:
            response = self._client.is_authorized(
                policyStoreId=self._policy_store_id,
                principal=self._build_principal(identity_context),
                action=self._build_action(request),
                resource=self._build_resource(request),
                entities=self._build_entities(
                    identity_context=identity_context,
                    request=request,
                ),
                context=self._build_context(request),
            )
        except (BotoCoreError, ClientError):
            return AuthorizationDecision(
                effect=AuthorizationEffect.DENY,
                reason="Authorization provider unavailable or request failed",
                policy_id="VERIFIED_PERMISSIONS_FAILURE",
                decision_id=str(uuid4()),
                request_id=request_id,
            )

        evaluation_errors = response.get("errors", [])

        if evaluation_errors:
            return AuthorizationDecision(
                effect=AuthorizationEffect.DENY,
                reason="Amazon Verified Permissions policy evaluation error",
                policy_id="VERIFIED_PERMISSIONS_EVALUATION_ERROR",
                decision_id=str(uuid4()),
                request_id=request_id,
            )

        aws_decision = response["decision"]

        effect = (
            AuthorizationEffect.ALLOW
            if aws_decision == "ALLOW"
            else AuthorizationEffect.DENY
        )

        determining_policies = response.get(
            "determiningPolicies",
            [],
        )

        policy_ids = [
            item["policyId"]
            for item in determining_policies
            if "policyId" in item
        ]

        policy_id = (
            ",".join(policy_ids)
            if policy_ids
            else "VERIFIED_PERMISSIONS_DEFAULT_DENY"
        )

        return AuthorizationDecision(
            effect=effect,
            reason="Amazon Verified Permissions authorization decision",
            policy_id=policy_id,
            decision_id=str(uuid4()),
            request_id=request_id,
        )

    @staticmethod
    def _build_principal(
        identity_context: IdentityContext,
    ) -> dict[str, str]:
        return {
            "entityType": "AegisAI::User",
            "entityId": identity_context.identity.user_id,
        }

    @staticmethod
    def _build_action(
        request: AuthorizationRequest,
    ) -> dict[str, str]:
        action_map = {
            ("KnowledgeBase", "Read"): "ReadKnowledgeBase",
            ("Model", "Invoke"): "InvokeModel",
            ("Tool", "Invoke"): "InvokeTool",
        }

        cedar_action = action_map.get(
            (
                request.resource.resource_type,
                request.action,
            )
        )

        if cedar_action is None:
            raise ValueError(
                "No Cedar action mapping exists for "
                f"{request.resource.resource_type}:{request.action}"
            )

        return {
            "actionType": "AegisAI::Action",
            "actionId": cedar_action,
        }

    @staticmethod
    def _build_resource(
        request: AuthorizationRequest,
    ) -> dict[str, str]:
        return {
            "entityType": (
                f"AegisAI::{request.resource.resource_type}"
            ),
            "entityId": request.resource.resource_id,
        }

    @staticmethod
    def _build_entities(
        *,
        identity_context: IdentityContext,
        request: AuthorizationRequest,
    ) -> dict[str, list[dict[str, Any]]]:
        clearance_level = _CLEARANCE_LEVELS.get(
            identity_context.identity.clearance
        )

        if clearance_level is None:
            raise ValueError(
                "Unknown principal clearance classification"
            )

        resource_classification = _CLEARANCE_LEVELS.get(
            request.resource.classification
        )

        if resource_classification is None:
            raise ValueError(
                "Unknown resource classification"
            )

        principal_attributes: dict[str, Any] = {
            "department": {
                "string": identity_context.identity.department
            },
            "role": {
                "string": identity_context.identity.role
            },
            "clearanceLevel": {
                "long": clearance_level
            },
            "allowedModels": {
                "set": [
                    {"string": model}
                    for model in identity_context.allowed_models
                ]
            },
            "allowedTools": {
                "set": [
                    {"string": tool}
                    for tool in identity_context.allowed_tools
                ]
            },
        }

        resource_attributes: dict[str, Any] = {
            "ownerDepartment": {
                "string": request.resource.owner_department
            },
            "classificationLevel": {
                "long": resource_classification
            },
            "environment": {
                "string": request.resource.environment
            },
        }

        if request.resource.resource_type == "Model":
            resource_attributes["modelId"] = {
                "string": request.resource.resource_id
            }

        if request.resource.resource_type == "Tool":
            resource_attributes["toolId"] = {
                "string": request.resource.resource_id
            }

        return {
            "entityList": [
                {
                    "identifier": {
                        "entityType": "AegisAI::User",
                        "entityId": identity_context.identity.user_id,
                    },
                    "attributes": principal_attributes,
                    "parents": [],
                },
                {
                    "identifier": {
                        "entityType": (
                            f"AegisAI::{request.resource.resource_type}"
                        ),
                        "entityId": request.resource.resource_id,
                    },
                    "attributes": resource_attributes,
                    "parents": [],
                },
            ]
        }

    @staticmethod
    def _build_context(
        request: AuthorizationRequest,
    ) -> dict[str, Any]:
        return {
            "contextMap": {
                key: {
                    "string": str(value)
                }
                for key, value in request.context.items()
            }
        }
