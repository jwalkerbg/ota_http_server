"""Tests for the centralized password policy."""

import pytest

from ota_http_server.core.password_policy import (
    DEFAULT_MAX_LENGTH,
    DEFAULT_MIN_LENGTH,
    PasswordPolicy,
    PasswordPolicyError,
)


def test_defaults_are_applied():
    policy = PasswordPolicy()

    assert policy.min_length == DEFAULT_MIN_LENGTH
    assert policy.max_length == DEFAULT_MAX_LENGTH


def test_from_mapping_uses_configured_values():
    policy = PasswordPolicy.from_mapping(
        {"password_min_length": 12, "password_max_length": 64}
    )

    assert policy.min_length == 12
    assert policy.max_length == 64


def test_from_mapping_falls_back_to_defaults_for_missing_or_none():
    assert PasswordPolicy.from_mapping(None) == PasswordPolicy()
    assert PasswordPolicy.from_mapping({}) == PasswordPolicy()
    assert PasswordPolicy.from_mapping(
        {"password_min_length": None, "password_max_length": None}
    ) == PasswordPolicy()


def test_from_mapping_accepts_string_values_from_environment():
    policy = PasswordPolicy.from_mapping(
        {"password_min_length": "10", "password_max_length": "128"}
    )

    assert policy.min_length == 10
    assert policy.max_length == 128


def test_validate_accepts_password_meeting_policy():
    PasswordPolicy().validate("a" * DEFAULT_MIN_LENGTH)


def test_validate_rejects_empty_password():
    with pytest.raises(PasswordPolicyError, match="must not be empty"):
        PasswordPolicy().validate("")


def test_validate_rejects_non_string_password():
    with pytest.raises(PasswordPolicyError, match="must not be empty"):
        PasswordPolicy().validate(None)


def test_validate_rejects_too_short_password():
    with pytest.raises(PasswordPolicyError, match="at least"):
        PasswordPolicy().validate("a" * (DEFAULT_MIN_LENGTH - 1))


def test_validate_rejects_too_long_password():
    with pytest.raises(PasswordPolicyError, match="at most"):
        PasswordPolicy().validate("a" * (DEFAULT_MAX_LENGTH + 1))


def test_error_messages_never_contain_the_password():
    secret = "super-secret-value"
    with pytest.raises(PasswordPolicyError) as excinfo:
        PasswordPolicy(min_length=100).validate(secret)

    assert secret not in str(excinfo.value)


def test_validate_with_confirmation_accepts_matching_pair():
    PasswordPolicy().validate_with_confirmation("valid-password", "valid-password")


def test_validate_with_confirmation_rejects_mismatch():
    with pytest.raises(PasswordPolicyError, match="does not match"):
        PasswordPolicy().validate_with_confirmation("valid-password", "other-password")


def test_validate_with_confirmation_rejects_empty_confirmation():
    with pytest.raises(PasswordPolicyError, match="must not be empty"):
        PasswordPolicy().validate_with_confirmation("valid-password", "")


def test_validate_with_confirmation_checks_policy_before_confirmation():
    with pytest.raises(PasswordPolicyError, match="at least"):
        PasswordPolicy().validate_with_confirmation("short", "short")
