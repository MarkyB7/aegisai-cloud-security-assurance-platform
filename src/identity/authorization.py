"""
Enterprise authorization for the AegisAI identity subsystem.

The module provides a policy-driven authorization boundary while keeping
the rest of AegisAI independent from a specific policy provider.

A future adapter can delegate policy evaluation to Amazon Verified
Permissions and Cedar without changing downstream callers.
"""

from collections.abc import Sequence
from uuid import uuid4

from .exceptions import AuthorizationError
from .models import (
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationRequest,
    IdentityContext,
    Permission,
)


_CLASSIFICATION_LEVELS = {
    "Public": 0,
    "Internal": 1,
    "Confidential": 2,
    "Restricted": 3,
}


class AuthorizationService:
    """
    Policy Decision Point for AegisAI authorization.

    Version 1 evaluates local enterprise policy rules. The public interface
    is intentionally provider-neutral so a Cedar / Amazon Verified
    Permissions adapter can replace local evaluation later.
    """

    def authorize(
        self,
        *,
        identity_context: IdentityContext,
        request: AuthorizationRequest,
    ) -> AuthorizationDecision:
        """
        Evaluate whether an authenticated identity may perform an action.

        The policy model combines:

        - authentication state,
        - explicit permissions,
        - department attributes,
        - clearance / classification,
        - model and tool restrictions,
        - resource environment.

        Default behavior is DENY.
        """
        request_id = identity_context.request_id or str(uuid4())

        if not identity_context.authenticated:
            return self._deny(
                reason="Principal is not authenticated",
                policy_id="AUTHN_REQUIRED",
                request_id=request_id,
            )

        explicit_permission = self._has_permission(
            permissions=identity_context.permissions,
            resource=request.resource.resource_type,
            action=request.action,
        )

        if not explicit_permission:
            return self._deny(
                reason="Required resource/action permission is not granted",
                policy_id="LEAST_PRIVILEGE",
                request_id=request_id,
            )

        if not self._department_allowed(
            principal_department=identity_context.identity.department,
            owner_department=request.resource.owner_department,
        ):
            return self._deny(
                reason="Cross-department resource access is not permitted",
                policy_id="DEPARTMENT_BOUNDARY",
                request_id=request_id,
            )

        if not self._clearance_sufficient(
            clearance=identity_context.identity.clearance,
            classification=request.resource.classification,
        ):
            return self._deny(
                reason="Identity clearance is insufficient for resource classification",
                policy_id="DATA_CLASSIFICATION",
                request_id=request_id,
            )

        model_name = request.context.get("model")

        if model_name is not None and model_name not in identity_context.allowed_models:
            return self._deny(
                reason="Requested AI model is not authorized for this identity",
                policy_id="MODEL_ALLOWLIST",
                request_id=request_id,
            )

        tool_name = request.context.get("tool")

        if tool_name is not None and tool_name not in identity_context.allowed_tools:
            return self._deny(
                reason="Requested enterprise tool is not authorized for this identity",
                policy_id="TOOL_ALLOWLIST",
                request_id=request_id,
            )

        if request.resource.environment.lower() == "production":
            if identity_context.identity.role.lower() == "intern":
                return self._deny(
                    reason="Intern identities may not access production resources",
                    policy_id="PRODUCTION_ACCESS",
                    request_id=request_id,
                )

        return AuthorizationDecision(
            effect=AuthorizationEffect.ALLOW,
            reason="All applicable authorization policies were satisfied",
            policy_id="COMPOSITE_ENTERPRISE_POLICY",
            decision_id=str(uuid4()),
            request_id=request_id,
        )

    @staticmethod
    def _has_permission(
        *,
        permissions: Sequence[Permission],
        resource: str,
        action: str,
    ) -> bool:
        return any(
            permission.resource == resource
            and permission.action == action
            for permission in permissions
        )

    @staticmethod
    def _department_allowed(
        *,
        principal_department: str,
        owner_department: str,
    ) -> bool:
        return principal_department.casefold() == owner_department.casefold()

    @staticmethod
    def _clearance_sufficient(
        *,
        clearance: str,
        classification: str,
    ) -> bool:
        principal_level = _CLASSIFICATION_LEVELS.get(clearance)
        resource_level = _CLASSIFICATION_LEVELS.get(classification)

        if principal_level is None or resource_level is None:
            return False

        return principal_level >= resource_level

    @staticmethod
    def _deny(
        *,
        reason: str,
        policy_id: str,
        request_id: str,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            effect=AuthorizationEffect.DENY,
            reason=reason,
            policy_id=policy_id,
            decision_id=str(uuid4()),
            request_id=request_id,
        )


def enforce_authorization(decision: AuthorizationDecision) -> None:
    """
    Policy Enforcement Point.

    Denied decisions raise AuthorizationError. Allowed decisions return
    without error.
    """
    if not decision.allowed:
        raise AuthorizationError(
            f"Authorization denied by {decision.policy_id}: {decision.reason}"
        )
