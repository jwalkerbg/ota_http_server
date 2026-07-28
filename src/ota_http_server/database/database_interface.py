# database_interface.py

from typing import Protocol

class DatabaseInterface(Protocol):

    def init_db(self) -> None:
        ...

    def migrate(self) -> None:
        ...

    def rollback(self) -> None:
        ...

