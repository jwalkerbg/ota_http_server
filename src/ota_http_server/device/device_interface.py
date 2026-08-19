# device_interface.py

from typing import Protocol

class DeviceInterface(Protocol):

    def command_handler(self) -> None:
        ...
