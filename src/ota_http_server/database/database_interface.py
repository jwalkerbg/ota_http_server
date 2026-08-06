# database_interface.py

from typing import Protocol

from ota_http_server.core.data_models import User, Project

class DatabaseInterface(Protocol):

    def init_db(self) -> None:
        ...

    def migrate(self) -> None:
        ...

    def rollback(self) -> None:
        ...

    def add_user(self, user: User) -> User:
        ...

    def enable_user_by_id(self, user_id: int) -> None:
        ...

    def enable_user_by_username(self, username: str) -> None:
        ...

    def disable_user_by_id(self, user_id: int) -> None:
        ...

    def disable_user_by_username(self, username: str) -> None:
        ...

    def user_get_by_id(self, user_id: int) -> User | None:
        ...

    def user_get_by_username(self, username: str) -> User | None:
        ...

    def user_get_list(self) -> list[User]:
        ...

    def add_project(self, project: Project) -> Project:
        ...