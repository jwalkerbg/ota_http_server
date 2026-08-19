# projects_interface.py

from typing import Protocol

class ProjectInterface(Protocol):

    def command_handler(self) -> None:
        ...
