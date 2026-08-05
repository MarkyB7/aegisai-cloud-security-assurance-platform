"""
Tests for the AegisAI authentication service.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.identity.auth import AuthenticationService, extract_bearer_token
from src.identity.exceptions import AuthenticationError, TokenValidationError
from src.identity.jwt_validator import JWTValidator


ISSUER = "https://identity.aegisai.example.com"
AUDIENCE = "aegisai-api"


@pytest.fixture(scope="module")
def signing_keys() -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


@pytest.fixture
def authentication_service(
    signing_keys: tuple[str, str],
) -> AuthenticationService:
    _, public_key = signing_keys

    validator = JWTValidator(
        public_key=public_key,
        issuer=ISSUER,
        audience=AUDIENCE,
        required_token_use="access",
        leeway_seconds=0,
    )

    return AuthenticationService(jwt_validator=validator)


def create_token(private_key: str) -> str:
    now = datetime.now(timezone.utc)

    claims = {
        "sub": "user-12345",
        "username": "alice",
        "email": "alice@example.com",
        "department": "Finance",
        "role": "Financial Analyst",
        "clearance": "Confidential",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "token_use": "access",
    }

    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
    )


def test_authenticate_builds_identity_context(
    signing_keys: tuple[str, str],
    authentication_service: AuthenticationService,
) -> None:
    private_key, _ = signing_keys
    token = create_token(private_key)

    context = authentication_service.authenticate(
        token=token,
        session_id="session-123",
        request_id="request-123",
    )

    assert context.authenticated is True
    assert context.authorized is False
    assert context.identity.user_id == "user-12345"
    assert context.identity.username == "alice"
    assert context.identity.department == "Finance"
    assert context.session_id == "session-123"
    assert context.request_id == "request-123"


def test_authenticate_propagates_invalid_token_error(
    authentication_service: AuthenticationService,
) -> None:
    with pytest.raises(TokenValidationError):
        authentication_service.authenticate(
            token="invalid-token",
            session_id="session-123",
        )


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc.def.ghi", "abc.def.ghi"),
        ("bearer abc.def.ghi", "abc.def.ghi"),
        ("  Bearer abc.def.ghi  ", "abc.def.ghi"),
    ],
)
def test_extract_bearer_token_accepts_valid_headers(
    header: str,
    expected: str,
) -> None:
    assert extract_bearer_token(header) == expected


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Basic abc.def.ghi",
        "Bearer",
        "Bearer ",
        "Bearer abc def",
    ],
)
def test_extract_bearer_token_rejects_invalid_headers(
    header: str | None,
) -> None:
    with pytest.raises(AuthenticationError):
        extract_bearer_token(header)
