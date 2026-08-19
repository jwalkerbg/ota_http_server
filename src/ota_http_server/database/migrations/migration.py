# migration.py

from abc import ABC, abstractmethod
from typing import Any

class Migration(ABC):
    """Base class for all database migrations."""

    version: int
    description: str

    @abstractmethod
    def up(self, conn: Any) -> None:
        """Apply the migration."""
        pass

    @abstractmethod
    def down(self, conn: Any) -> None:
        """Rollback the migration."""
        pass
