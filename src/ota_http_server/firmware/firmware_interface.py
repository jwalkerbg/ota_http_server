# firmware_interface.py

from typing import Protocol

class FirmwareInterface(Protocol):

    def command_handler(self) -> None:
        ...
