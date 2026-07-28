# firmware_interface.py

from typing import Protocol

class FirmwareService(Protocol):

    def add_firmware(self) -> int:
        ...

    def get_firmware(self) -> int | None:
        ...
