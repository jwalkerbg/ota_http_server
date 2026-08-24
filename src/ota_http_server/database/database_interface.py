# database_interface.py

from typing import Protocol

from ota_http_server.core.data_models import User, Project, ProjectListItem, Target, Device, DeviceListItem, Firmware, FirmwareListItem, FirmwareDeleteInfo

class DatabaseInterface(Protocol):

    def init_db(self) -> None:
        ...

    def migrate(self) -> None:
        ...

    def rollback(self) -> None:
        ...

    def user_add(self, user: User) -> User:
        ...

    def user_enable_by_id(self, user_id: int) -> None:
        ...

    def user_enable_by_username(self, username: str) -> None:
        ...

    def user_disable_by_id(self, user_id: int) -> None:
        ...

    def user_disable_by_username(self, username: str) -> None:
        ...

    def user_get_by_id(self, user_id: int) -> User | None:
        ...

    def user_get_by_username(self, username: str) -> User | None:
        ...

    def user_is_active(self, user_id: int) -> bool:
        ...

    def user_get_list(self, is_active: bool | None = None) -> list[User]:
        ...

    def user_get_record(self, is_active: bool | None = None) -> list[User]:
        ...

    def project_add(self, project: Project) -> Project:
        ...

    def project_enable_by_id(self, id: int) -> None:
        ...

    def project_enable_by_name(self, name: str) -> None:
        ...

    def project_disable_by_id(self, id: int) -> None:
        ...

    def project_disable_by_name(self, name: str) -> None:
        ...

    def project_get_by_id(self, id: int) -> Project | None:
        ...

    def project_get_by_name(self, name: str) -> Project | None:
        ...

    def project_is_active(self, project_id: int) -> bool:
        ...

    def project_get_record(self) -> list[Project]:
        ...

    def project_get_list(self) -> list[ProjectListItem]:
        ...

    def target_add(self, target: Target) -> Target:
        ...

    def target_get_by_id(self, id: int) -> Target | None:
        ...

    def target_get_by_name(self, name: str) -> Target | None:
        ...

    def target_get_list(self) -> list[Target]:
        ...

    def device_add(self, device: Device) -> Device:
        ...

    def device_change_target_by_id(self, id: int, target_id: int) -> None:
        ...

    def device_change_target_by_name(self, name: str, target_id: int) -> None:
        ...

    def device_enable_by_id(self, id: int) -> None:
        ...

    def device_enable_by_name(self, name: str) -> None:
        ...

    def device_disable_by_id(self, id: int) -> None:
        ...

    def device_disable_by_name(self, name: str) -> None:
        ...

    def device_get_by_id(self, id: int) -> Device | None:
        ...

    def device_get_by_name(self, name: str) -> Device | None:
        ...

    def device_is_active(self, device_id: int) -> bool:
        ...

    def device_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Device]:
        ...

    def device_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[DeviceListItem]:
        ...

    def firmware_add(self, firmware: Firmware) -> Firmware:
        ...

    def firmware_change_target_by_id(self, id: int, target_id: int) -> None:
        ...

    def firmware_change_target_by_project_version(self, project_id: int, version: str, target_id: int) -> None:
        ...

    def firmware_replace(self, firmware_id: int, filename: str, file_size: int, checksum: str) -> Firmware:
        ...

    def firmware_delete_by_id(self, firmware_id: int) -> FirmwareDeleteInfo:
        ...

    def firmware_delete_by_project_version(
        self,
        project_id: int,
        version: str,
    ) -> FirmwareDeleteInfo:
        ...

    def firmware_enable_by_id(self, id: int) -> None:
        ...

    def firmware_enable_by_project_version(self, project_id: int, version: str) -> None:
        ...

    def firmware_disable_by_id(self, id: int) -> None:
        ...

    def firmware_disable_by_project_version(self, project_id: int, version: str) -> None:
        ...

    def firmware_get_by_id(self, id: int) -> Firmware | None:
        ...

    def firmware_get_by_project_version(self, project_id: int, version: str,) -> Firmware | None:
        ...

    def firmware_is_active(self, firmware_id: int) -> bool:
        ...

    def firmware_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Firmware]:
        ...

    def firmware_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[FirmwareListItem]:
        ...
