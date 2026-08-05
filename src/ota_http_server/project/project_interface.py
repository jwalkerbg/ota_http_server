# projects_interface.py

from typing import Protocol

class ProjectService(Protocol):

    def command_handler(self) -> None:
        ...
