"""Validation shared by user database backends."""


def validate_user_name(name: str) -> str:
    if len(name) > 1024:
        raise ValueError("Name must not exceed 1024 characters")
    return name
