# migration.py

from abc import ABC, abstractmethod
import sqlite3

class Migration(ABC):
    """Base class for all database migrations."""

    version: int
    description: str

    @abstractmethod
    def up(self, conn: sqlite3.Connection) -> None:
        """Apply the migration."""
        pass

    @abstractmethod
    def down(self, conn: sqlite3.Connection) -> None:
        """Rollback the migration."""
        pass
