# devices_interface.py

from typing import Protocol

class DeviceService(Protocol):

    def add_device(self, device_name: str, device_uuid: str) -> int:
        ...

    def get_device(self, device_id: int) -> dict | None:
        ...

    def update_device(self, device_id: int, device_name: str, device_uuid: str) -> bool:
        ...

    def delete_device(self, device_id: int) -> bool:
        ...
