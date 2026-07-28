# projects_interface.py

from typing import Protocol

class ProjectService(Protocol):

    def add_project(self, project_name: str, project_uuid: str, project_path: str) -> int:
        ...

    def get_project(self, project_id: int) -> dict | None:
        ...

    def update_project(self, project_id: int, project_name: str, project_uuid: str, project_path: str) -> bool:
        ...

    def delete_project(self, project_id: int) -> bool:
        ...
