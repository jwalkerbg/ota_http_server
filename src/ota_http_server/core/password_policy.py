# core/password_policy.py
"""Centralized password validation shared by the CLI, REST API and service layer.

The policy is intentionally modest so it does not interfere with password
managers or generated passwords: only length limits are enforced. Both limits
are configurable through the ``password_min_length`` / ``password_max_length``
parameters (configuration file, environment variables).

Error messages never include the password being validated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

DEFAULT_MIN_LENGTH = 8
# Generous upper bound, present only to reject abusive payloads; Argon2 itself
# accepts passwords of arbitrary length.
DEFAULT_MAX_LENGTH = 1024


class PasswordPolicyError(ValueError):
    """Raised when a password or its confirmation fails validation."""


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = DEFAULT_MIN_LENGTH
    max_length: int = DEFAULT_MAX_LENGTH

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any] | None) -> "PasswordPolicy":
        """Build a policy from a parameters mapping, falling back to defaults."""
        mapping = mapping or {}
        min_length = mapping.get("password_min_length") or DEFAULT_MIN_LENGTH
        max_length = mapping.get("password_max_length") or DEFAULT_MAX_LENGTH
        return cls(min_length=int(min_length), max_length=int(max_length))

    def validate(self, password: str, *, field: str = "new_password") -> None:
        """Validate a single password against the policy.

        Raises:
            PasswordPolicyError: if the password is empty or violates the policy.
        """
        if not isinstance(password, str) or password == "":
            raise PasswordPolicyError(f"Field '{field}' must not be empty")
        if len(password) < self.min_length:
            raise PasswordPolicyError(
                f"Field '{field}' must be at least {self.min_length} characters long"
            )
        if len(password) > self.max_length:
            raise PasswordPolicyError(
                f"Field '{field}' must be at most {self.max_length} characters long"
            )

    def validate_with_confirmation(
        self,
        password: str,
        confirm_password: str,
        *,
        field: str = "new_password",
        confirm_field: str = "confirm_password",
    ) -> None:
        """Validate a password together with its confirmation."""
        self.validate(password, field=field)
        if not isinstance(confirm_password, str) or confirm_password == "":
            raise PasswordPolicyError(f"Field '{confirm_field}' must not be empty")
        if password != confirm_password:
            raise PasswordPolicyError(
                f"Field '{confirm_field}' does not match field '{field}'"
            )
