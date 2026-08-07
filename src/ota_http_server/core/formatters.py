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

    COLUMNS = [
        Column('ID', ID_WIDTH, ">"),
        Column('Username', USERNAME_WIDTH),
        Column('Email', EMAIL_WIDTH),
        Column('Role', ROLE_WIDTH),
        Column('Status', STATUS_WIDTH),
        Column('Created At', DATE_WIDTH),
        Column('Updated At', DATE_WIDTH)
    ]

    @classmethod
    def header(cls) -> str:
        return "".join(
            f"{column.title:<{column.width}}"
            for column in cls.COLUMNS
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

        values = [
            str(user.id),
            user.username,
            user.email,
            user.role,
            status,
            created,
            updated
        ]

        widths = [column.width for column in cls.COLUMNS]

        return TableFormatter.format_row(values, widths)

    @classmethod
    def format_list(cls, items: list[User]) -> str:

        lines = [
            cls.header(),
            cls.separator(),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)

class ProjectFormatter:

    ID_WIDTH =  5
    NAME_WIDTH = 10
    USERNAME_WIDTH = 20
    DISPLAY_NAME_WIDTH = 32
    DESCRIPTION_WIDTH = 48
    CREATED_BY_WIDTH = 20
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    COLUMNS = [
        Column('ID', ID_WIDTH, ">"),
        Column('Name', NAME_WIDTH),
        Column('Display name', DISPLAY_NAME_WIDTH),
        Column('Description', DESCRIPTION_WIDTH),
        Column('Created by', CREATED_BY_WIDTH),
        Column('Status', STATUS_WIDTH),
        Column('Created At', DATE_WIDTH),
        Column('Updated At', DATE_WIDTH)
    ]

    @classmethod
    def header(cls) -> str:
        return "".join(
            f"{column.title:<{column.width}}"
            for column in cls.COLUMNS
        )

    @classmethod
    def separator(cls) -> str:
        return "-" * len(cls.header())

    @classmethod
    def format(cls, project: Project) -> list[str]:
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

        values = [
            str(project.id),
            project.name,
            project.display_name,
            project.description,
            str(project.created_by),
            status,
            created,
            updated
        ]

        widths = [column.width for column in cls.COLUMNS]

        return TableFormatter.format_row(values, widths)

    @classmethod
    def format_list(cls, items: list[Project]) -> str:

        lines = [
            cls.header(),
            cls.separator(),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)

class DeviceFormatter:
    ID_WIDTH =  5
    DEVICE_UUID_WIDTH = 36
    PROJECT_NAME_WIDTH = 10
    MODEL_WIDTH = 16
    SERIALN_WIDTH = 32
    CURRENT_VERSION_WIDTH = 32
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    COLUMNS = [
        Column('ID', ID_WIDTH, ">"),
        Column('UUID', DEVICE_UUID_WIDTH),
        Column('Project', PROJECT_NAME_WIDTH),
        Column('Model', MODEL_WIDTH),
        Column('Serial #', SERIALN_WIDTH),
        Column('Current version', CURRENT_VERSION_WIDTH),
        Column('Last seen', DATE_WIDTH),
        Column('Status', STATUS_WIDTH),
        Column('Created At', DATE_WIDTH),
        Column('Updated At', DATE_WIDTH)
    ]

    @classmethod
    def header(cls) -> str:
        return "".join(
            f"{column.title:<{column.width}}"
            for column in cls.COLUMNS
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

        values = [
            str(device.id),
            device.uuid,
            str(device.project_id),
            device.model,
            device.serial_number,
            device.current_version,
            device.last_seen,
            status,
            created,
            updated
        ]

        widths = [column.width for column in cls.COLUMNS]

        return TableFormatter.format_row(values, widths)
    @classmethod
    def format_list(cls, items: list[Device]) -> str:

        lines = [
            cls.header(),
            cls.separator(),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)

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

    COLUMNS = [
        Column('ID', ID_WIDTH, ">"),
        Column('Project', PROJECT_NAME_WIDTH),
        Column('Version', VERSION_WIDTH),
        Column('FileName', FILENAME_WIDTH),
        Column('FileSize', FILESIZE_WIDTH),
        Column('Checksum', FILECHECKSUM_WIDTH),
        Column('Release notes', RELEASE_NOTES),
        Column('Channel', CHANNEL_WIDTH),
        Column('Created At', DATE_WIDTH),
        Column('Updated At', DATE_WIDTH)
    ]

    @classmethod
    def header(cls) -> str:
        return "".join(
            f"{column.title:<{column.width}}"
            for column in cls.COLUMNS
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
            str(firmware.id),
            str(firmware.project_id),
            firmware.version,
            firmware.filename,
            firmware.file_size,
            firmware.checksum,
            firmware.release_notes,
            firmware.channel,
            created,
            updated
        )

        widths = [column.width for column in cls.COLUMNS]

        return TableFormatter.format_row(values, widths)

    @classmethod
    def format_list(cls, items: list[Firmware]) -> str:

        lines = [
            cls.header(),
            cls.separator(),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)