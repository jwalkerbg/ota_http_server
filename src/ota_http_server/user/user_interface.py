# users_interface.py

from typing import Protocol

class UserInterface(Protocol):

    def command_handler(self) -> None:
        ...
