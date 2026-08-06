# firmware_interface.py

from typing import Protocol

class FirmwareService(Protocol):

    def command_handler(self) -> None:
        ...
