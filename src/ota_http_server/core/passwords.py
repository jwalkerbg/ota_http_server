# passwords.py

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class Passwords:
    """Utility functions for password hashing and verification."""

    _hasher = PasswordHasher()

    @staticmethod
    def hash(password: str) -> str:
        """
        Hash a plaintext password.

        Returns:
            Encoded Argon2 hash suitable for database storage.
        """
        return Passwords._hasher.hash(password)

    @staticmethod
    def verify(password: str, password_hash: str) -> bool:
        """
        Verify a plaintext password against a stored hash.
        """
        try:
            return Passwords._hasher.verify(password_hash, password)
        except VerifyMismatchError:
            return False

    @staticmethod
    def needs_rehash(password_hash: str) -> bool:
        """
        Returns True if the stored hash should be regenerated using
        the current Argon2 parameters.
        """
        return Passwords._hasher.check_needs_rehash(password_hash)