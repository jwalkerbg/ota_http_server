# core/formatters.py

from datetime import datetime
from textwrap import wrap
from ota_http_server.core.data_models import User, Project, Device, Firmware, Column

class TableFormatter:

    @staticmethod
    def format_row(
        values: list[str],
        widths: list[int],
    ) -> list[str]:

        # Wrap every cell.
        wrapped = [
            wrap(value, width=width) or [""]
            for value, width in zip(values, widths)
        ]

        # Maximum number of physical lines.
        height = max(len(cell) for cell in wrapped)

        # Pad all columns to equal height.
        for cell in wrapped:
            cell.extend([""] * (height - len(cell)))

        # Produce formatted output lines.
        result = []

        for row in range(height):
            line = "".join(
                f"{wrapped[col][row]:<{widths[col]}}"
                for col in range(len(widths))
            )
            result.append(line)

        return result

class UserFormatter:

    ID_WIDTH =  5
    USERNAME_WIDTH =  20
    EMAIL_WIDTH =  30
    ROLE_WIDTH =  12
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    @classmethod
    def header(cls) -> str:
        return (
            f"{'ID':<{cls.ID_WIDTH}}"
            f"{'Username':<{cls.USERNAME_WIDTH}}"
            f"{'Email':<{cls.EMAIL_WIDTH}}"
            f"{'Role':<{cls.ROLE_WIDTH}}"
            f"{'Status':<{cls.STATUS_WIDTH}}"
            f"{'Created At':<{cls.DATE_WIDTH}}"
            f"{'Updated At':<{cls.DATE_WIDTH}}"
        )

    @classmethod
    def separator(cls) -> str:
        return "-" * len(cls.header())

    @classmethod
    def format(cls, user: User) -> str:
        status = "active" if user.is_active else "disabled"

        created = (
            user.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if user.created_at
            else "-"
        )

        updated = (
            user.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if user.updated_at
            else "-"
        )

        return (
            f"{user.id:<{cls.ID_WIDTH}}"
            f"{user.username:<{cls.USERNAME_WIDTH}}"
            f"{user.email:<{cls.EMAIL_WIDTH}}"
            f"{user.role:<{cls.ROLE_WIDTH}}"
            f"{status:<{cls.STATUS_WIDTH}}"
            f"{created:<{cls.DATE_WIDTH}}"
            f"{updated:<{cls.DATE_WIDTH}}"
        )

class ProjectFormatter:

    ID_WIDTH =  5
    NAME_WIDTH = 10
    USERNAME_WIDTH = 20
    DISPLAY_NAME_WIDTH = 32
    DESCRIPTION_WIDTH = 48
    CREATED_BY_WIDTH = 20
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    @classmethod
    def header(cls) -> str:
        return (
            f"{'ID':<{cls.ID_WIDTH}}"
            f"{'Name':<{cls.NAME_WIDTH}}"
            f"{'Display name':<{cls.DISPLAY_NAME_WIDTH}}"
            f"{'Description':<{cls.DESCRIPTION_WIDTH}}"
            f"{'Created by':<{cls.CREATED_BY_WIDTH}}"
            f"{'Status':<{cls.STATUS_WIDTH}}"
            f"{'Created At':<{cls.DATE_WIDTH}}"
            f"{'Updated At':<{cls.DATE_WIDTH}}"
        )

    @classmethod
    def separator(cls) -> str:
        return "-" * len(cls.header())

    @classmethod
    def format(cls, project: Project) -> str:
        status = "active" if project.is_active else "disabled"

        created = (
            project.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if project.created_at
            else "-"
        )

        updated = (
            project.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if project.updated_at
            else "-"
        )

        return (
            f"{project.id:<{cls.ID_WIDTH}}"
            f"{project.name:<{cls.NAME_WIDTH}}"
            f"{project.display_name:<{cls.DISPLAY_NAME_WIDTH}}"
            f"{project.description:<{cls.DESCRIPTION_WIDTH}}"
            f"{project.created_by:<{cls.CREATED_BY_WIDTH}}"
            f"{project.is_active:<{cls.STATUS_WIDTH}}"
            f"{created:<{cls.DATE_WIDTH}}"
            f"{updated:<{cls.DATE_WIDTH}}"
        )

class DeviceFormatter:
    ID_WIDTH =  5
    DEVICE_UUID_WIDTH = 36
    PROJECT_NAME_WIDTH = 10
    MODEL_WIDTH = 16
    SERIALN_WIDTH = 32
    CURRENT_VERSION_WIDTH = 32
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    @classmethod
    def header(cls) -> str:
        return (
            f"{'ID':<{cls.ID_WIDTH}}"
            f"{'UUID':<{cls.DEVICE_UUID_WIDTH}}"
            f"{'Project':<{cls.PROJECT_NAME_WIDTH}}"
            f"{'Model':<{cls.MODEL_WIDTH}}"
            f"{'Serial #':<{cls.SERIALN_WIDTH}}"
            f"{'Current version':<{cls.CURRENT_VERSION_WIDTH}}"
            f"{'Last seen':<{cls.DATE_WIDTH}}"
            f"{'Status':<{cls.STATUS_WIDTH}}"
            f"{'Created At':<{cls.DATE_WIDTH}}"
            f"{'Updated At':<{cls.DATE_WIDTH}}"
        )

    @classmethod
    def separator(cls) -> str:
        return "-" * len(cls.header())

    @classmethod
    def format(cls, device: Device) -> str:
        status = "active" if device.is_active else "disabled"

        last_seen = (
            device.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            if device.last_seen
            else "-"
        )

        created = (
            device.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if device.created_at
            else "-"
        )

        updated = (
            device.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if device.updated_at
            else "-"
        )

        return (
            f"{device.id:<{cls.ID_WIDTH}}"
            f"{device.device_id:<{cls.DEVICE_UUID_WIDTH}}"
            f"{device.project_id:<{cls.PROJECT_NAME_WIDTH}}"
            f"{device.model:<{cls.MODEL_WIDTH}}"
            f"{device.serial_number:<{cls.SERIALN_WIDTH}}"
            f"{device.current_version:<{cls.CURRENT_VERSION_WIDTH}}"
            f"{device.last_seen:<{cls.DATE_WIDTH}}"
            f"{status:<{cls.STATUS_WIDTH}}"
            f"{created:<{cls.DATE_WIDTH}}"
            f"{updated:<{cls.DATE_WIDTH}}"
        )

class FirmwareFormatter:
    ID_WIDTH =  5
    PROJECT_NAME_WIDTH = 10
    VERSION_WIDTH = 32
    FILENAME_WIDTH = 32
    FILESIZE_WIDTH = 10
    FILECHECKSUM_WIDTH = 10
    RELEASE_NOTES = 48
    CHANNEL_WIDTH = 10
    DATE_WIDTH =  22

    @classmethod
    def header(cls) -> str:
        return (
            f"{'ID':<{cls.ID_WIDTH}}"
            f"{'Project':<{cls.PROJECT_NAME_WIDTH}}"
            f"{'Version':<{cls.VERSION_WIDTH}}"
            f"{'FileName':<{cls.FILENAME_WIDTH}}"
            f"{'FileSize':<{cls.FILESIZE_WIDTH}}"
            f"{'Checksum':<{cls.FILECHECKSUM_WIDTH}}"
            f"{'Release notes':<{cls.RELEASE_NOTES}}"
            f"{'Channel':<{cls.CHANNEL_WIDTH}}"
            f"{'Created At':<{cls.DATE_WIDTH}}"
            f"{'Updated At':<{cls.DATE_WIDTH}}"
        )

    @classmethod
    def separator(cls) -> str:
        return "-" * len(cls.header())

    @classmethod
    def format(cls, firmware: Firmware) -> str:
        status = "active" if firmware.is_active else "disabled"

        created = (
            firmware.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if firmware.created_at
            else "-"
        )

        updated = (
            firmware.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if firmware.updated_at
            else "-"
        )

        return (
            f"{firmware.id:<{cls.ID_WIDTH}}"
            f"{firmware.project_id:<{cls.PROJECT_NAME_WIDTH}}"
            f"{firmware.version:<{cls.VERSION_WIDTH}}"
            f"{firmware.filename:<{cls.FILENAME_WIDTH}}"
            f"{firmware.file_size:<{cls.FILESIZE_WIDTH}}"
            f"{firmware.checksum:<{cls.FILECHECKSUM_WIDTH}}"
            f"{firmware.release_notes:<{cls.RELEASE_NOTES}}"
            f"{firmware.channel:<{cls.CHANNEL_WIDTH}}"
            f"{created:<{cls.DATE_WIDTH}}"
            f"{updated:<{cls.DATE_WIDTH}}"
        )
