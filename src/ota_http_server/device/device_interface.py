# device_interface.py

from typing import Protocol

class DeviceService(Protocol):

    def command_handler(self) -> None:
        ...
