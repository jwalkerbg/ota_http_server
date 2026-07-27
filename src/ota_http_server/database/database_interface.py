# database_interface.py

from typing import Protocol

class DatabaseInterface(Protocol):

    def init_db(self) -> None:
        ...

    def migrate(self) -> None:
        ...

    def add_user(self, name: str, email: str) -> int:
        ...

    def get_user(self, user_id: int) -> dict | None:
        ...

    def update_user(self, user_id: int, name: str, email: str) -> bool:
        ...

    def delete_user(self, user_id: int) -> bool:
        ...

    def add_device(self, device_name: str, device_uuid: str) -> int:
        ...

    def get_device(self, device_id: int) -> dict | None:
        ...

    def update_device(self, device_id: int, device_name: str, device_uuid: str) -> bool:
        ...

    def delete_device(self, device_id: int) -> bool:
        ...

    def add_project(self, project_name: str, project_uuid: str, project_path: str) -> int:
        ...

    def get_project(self, project_id: int) -> dict | None:
        ...

    def update_project(self, project_id: int, project_name: str, project_uuid: str, project_path: str) -> bool:
        ...

    def delete_project(self, project_id: int) -> bool:
        ...

    def close(self) -> None:
        ...
