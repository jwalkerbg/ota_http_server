from typing import Protocol


class TargetInterface(Protocol):
    def command_handler(self) -> None:
        ...
