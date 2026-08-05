"""
Security tests for the AegisAI JWT validator.

These tests generate a real RSA key pair and signed JWTs so validation
behavior is tested without depending on external AWS infrastructure.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.identity.exceptions import (
    MissingClaimError,
    TokenExpiredError,
    TokenValidationError,
)
from src.identity.jwt_validator import JWTValidator


ISSUER = "https://identity.aegisai.example.com"
AUDIENCE = "aegisai-api"
ALGORITHM = "RS256"


@pytest.fixture(scope="module")
def rsa_key_pair() -> tuple[str, str]:
    """
    Generate an RSA private/public key pair for test-token signing.
    """
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
def validator(rsa_key_pair: tuple[str, str]) -> JWTValidator:
    """
    Create a validator configured for the test issuer and audience.
    """
    _, public_key = rsa_key_pair

    return JWTValidator(
        public_key=public_key,
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithm=ALGORITHM,
        required_token_use="access",
        leeway_seconds=0,
    )


def build_claims(**overrides: object) -> dict[str, object]:
    """
    Build a valid baseline set of enterprise identity claims.
    """
    now = datetime.now(timezone.utc)

    claims: dict[str, object] = {
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

    claims.update(overrides)
    return claims


def sign_token(
    private_key: str,
    claims: dict[str, object],
) -> str:
    """
    Sign a test token with the generated RSA private key.
    """
    return jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        headers={"kid": "test-key-1"},
    )


def test_accepts_valid_signed_token(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair
    token = sign_token(private_key, build_claims())

    claims = validator.validate(token)

    assert claims["sub"] == "user-12345"
    assert claims["username"] == "alice"
    assert claims["department"] == "Finance"
    assert claims["token_use"] == "access"


def test_rejects_expired_token(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair
    now = datetime.now(timezone.utc)

    token = sign_token(
        private_key,
        build_claims(
            iat=now - timedelta(minutes=30),
            exp=now - timedelta(minutes=1),
        ),
    )

    with pytest.raises(TokenExpiredError, match="expired"):
        validator.validate(token)


def test_rejects_token_signed_by_untrusted_key(
    validator: JWTValidator,
) -> None:
    attacker_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    attacker_private_pem = attacker_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    forged_token = sign_token(
        attacker_private_pem,
        build_claims(),
    )

    with pytest.raises(TokenValidationError, match="signature"):
        validator.validate(forged_token)


def test_rejects_wrong_issuer(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair

    token = sign_token(
        private_key,
        build_claims(iss="https://attacker.example.com"),
    )

    with pytest.raises(TokenValidationError, match="issuer"):
        validator.validate(token)


def test_rejects_wrong_audience(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair

    token = sign_token(
        private_key,
        build_claims(aud="unauthorized-service"),
    )

    with pytest.raises(TokenValidationError, match="audience"):
        validator.validate(token)


def test_rejects_wrong_token_use(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair

    token = sign_token(
        private_key,
        build_claims(token_use="id"),
    )

    with pytest.raises(TokenValidationError, match="token_use"):
        validator.validate(token)


def test_rejects_missing_required_claim(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair
    claims = build_claims()
    claims.pop("department")

    token = sign_token(private_key, claims)

    with pytest.raises(MissingClaimError, match="department"):
        validator.validate(token)


def test_rejects_empty_identity_claim(
    rsa_key_pair: tuple[str, str],
    validator: JWTValidator,
) -> None:
    private_key, _ = rsa_key_pair

    token = sign_token(
        private_key,
        build_claims(role="   "),
    )

    with pytest.raises(MissingClaimError, match="role"):
        validator.validate(token)


def test_rejects_empty_token(
    validator: JWTValidator,
) -> None:
    with pytest.raises(TokenValidationError, match="non-empty"):
        validator.validate("")
