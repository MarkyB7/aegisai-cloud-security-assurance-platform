"""
Custom exceptions for the AegisAI identity subsystem.
"""


class IdentityError(Exception):
    """Base exception for identity-related failures."""


class AuthenticationError(IdentityError):
    """Raised when a requester cannot be authenticated."""


class TokenValidationError(AuthenticationError):
    """Raised when an identity token is invalid or cannot be trusted."""


class TokenExpiredError(TokenValidationError):
    """Raised when an identity token has expired."""


class AuthorizationError(IdentityError):
    """Raised when an authenticated identity is not authorized."""


class MissingClaimError(TokenValidationError):
    """Raised when a required token claim is missing."""
