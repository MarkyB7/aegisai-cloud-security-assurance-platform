from src.identity.evidence_policy import sanitize_authorization_record


def test_removes_sensitive_context_values() -> None:
    record = {
        "principal": {
            "user_id": "user-123",
            "username": "alice",
            "department": "Finance",
            "role": "Analyst",
            "clearance": "Confidential",
            "email": "alice@example.com",
        },
        "context": {
            "model": "Claude",
            "token": "secret-token-value",
            "password": "do-not-log-this",
        },
    }

    sanitized = sanitize_authorization_record(record)

    assert "email" not in sanitized["principal"]
    assert "token" not in sanitized["context"]
    assert "password" not in sanitized["context"]

    assert sanitized["principal"]["username"] == "alice"
    assert sanitized["context"]["model"] == "Claude"


def test_does_not_modify_original_record() -> None:
    record = {
        "principal": {
            "user_id": "user-123",
            "username": "alice",
            "email": "alice@example.com",
        }
    }

    sanitize_authorization_record(record)

    assert record["principal"]["email"] == "alice@example.com"
