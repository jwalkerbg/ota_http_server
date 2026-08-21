# core/formatters.py

from datetime import datetime
from textwrap import wrap
from ota_http_server.core.data_models import User, Project, ProjectListItem, Device, DeviceListItem, Firmware, FirmwareListItem, Column

class TableFormatter:

    SEPARATOR1 = " | "
    SEPARATOR2 = "-+-"

    @staticmethod
    def header(columns: list[Column]) -> str:
        return TableFormatter.SEPARATOR1.join(
            f"{column.title:{column.align}{column.width}}"
            for column in columns
        )

    @staticmethod
    def separator(columns: list[Column]) -> str:
        return TableFormatter.SEPARATOR2.join(
            "-" * column.width
            for column in columns
        )

    @staticmethod
    def format_row(
        values: list[str],
        columns: list[Column]
    ) -> list[str]:

        widths = [column.width for column in columns]
        alignments = [column.align for column in columns]

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
            line = TableFormatter.SEPARATOR1.join(
                f"{wrapped[col][row]:{alignments[col]}{widths[col]}}"
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
        Column('Username', USERNAME_WIDTH, "^"),
        Column('Email', EMAIL_WIDTH, "^"),
        Column('Role', ROLE_WIDTH, "^"),
        Column('Status', STATUS_WIDTH, "^"),
        Column('Created At', DATE_WIDTH, "^"),
        Column('Updated At', DATE_WIDTH, "^")
    ]

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

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[User]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
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
        Column('ID', ID_WIDTH, "^"),
        Column('Name', NAME_WIDTH, "^"),
        Column('Display name', DISPLAY_NAME_WIDTH, "^"),
        Column('Description', DESCRIPTION_WIDTH, "^"),
        Column('Created by', CREATED_BY_WIDTH, "^"),
        Column('Status', STATUS_WIDTH, "^"),
        Column('Created At', DATE_WIDTH, "^"),
        Column('Updated At', DATE_WIDTH, "^")
    ]

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
            project.display_name
                if project.display_name else "-",
            project.description
                if project.description else "-",
            str(project.created_by),
            status,
            created,
            updated
        ]

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[Project]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)

class ProjectListItemFormatter:

    ID_WIDTH =  5
    NAME_WIDTH = 10
    USERNAME_WIDTH = 20
    DISPLAY_NAME_WIDTH = 32
    DESCRIPTION_WIDTH = 48
    CREATED_BY_WIDTH = 20
    STATUS_WIDTH =  10

    COLUMNS = [
        Column('ID', ID_WIDTH, "^"),
        Column('Name', NAME_WIDTH, "^"),
        Column('Display name', DISPLAY_NAME_WIDTH, "^"),
        Column('Description', DESCRIPTION_WIDTH, "^"),
        Column('Created by', CREATED_BY_WIDTH, "^"),
        Column('Status', STATUS_WIDTH, "^")
    ]

    @classmethod
    def format(cls, project: ProjectListItem) -> list[str]:

        display_name = project.display_name if project.display_name else "-"
        description = project.description if project.description else "-"
        status = "active" if project.is_active else "disabled"

        values = [
            str(project.id),
            project.name,
            display_name
                if display_name else "-",
            description
                if description else "-",
            project.created_by_username,
            status
        ]

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[ProjectListItem]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
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
        Column('ID', ID_WIDTH, "^"),
        Column('UUID', DEVICE_UUID_WIDTH, "^"),
        Column('Project', PROJECT_NAME_WIDTH, "^"),
        Column('Model', MODEL_WIDTH, "^"),
        Column('Serial #', SERIALN_WIDTH, "^"),
        Column('Current version', CURRENT_VERSION_WIDTH, "^"),
        Column('Last seen', DATE_WIDTH, "^"),
        Column('Status', STATUS_WIDTH, "^"),
        Column('Created At', DATE_WIDTH, "^"),
        Column('Updated At', DATE_WIDTH, "^")
    ]

    @classmethod
    def format(cls, device: Device) -> str:
        status = "active" if device.is_active else "disabled"

        model = device.model if device.model else "-"
        serial_number = device.serial_number if device.serial_number else "-"
        current_version = device.current_version if device.current_version else "-"

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
            model,
            serial_number,
            current_version,
            last_seen,
            status,
            created,
            updated
        ]

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[Device]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)

class DeviceListItemFormatter:
    ID_WIDTH =  5
    DEVICE_UUID_WIDTH = 36
    PROJECT_NAME_WIDTH = 10
    MODEL_WIDTH = 16
    SERIALN_WIDTH = 32
    CURRENT_VERSION_WIDTH = 32
    DATE_WIDTH =  22
    STATUS_WIDTH =  10

    COLUMNS = [
        Column('ID', ID_WIDTH, "^"),
        Column('UUID', DEVICE_UUID_WIDTH, "^"),
        Column('Project', PROJECT_NAME_WIDTH, "^"),
        Column('Model', MODEL_WIDTH, "^"),
        Column('Serial #', SERIALN_WIDTH, "^"),
        Column('Current version', CURRENT_VERSION_WIDTH, "^"),
        Column('Last seen', DATE_WIDTH, "^"),
        Column('Status', STATUS_WIDTH, "^")
    ]

    @classmethod
    def format(cls, device: DeviceListItem) -> str:
        status = "active" if device.is_active else "disabled"

        model = device.model if device.model else "-"
        serial_number = device.serial_number if device.serial_number else "-"
        current_version = device.current_version if device.current_version else "-"

        last_seen = (
            device.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            if device.last_seen
            else "-"
        )

        values = [
            str(device.id),
            device.uuid,
            device.project_name,
            model,
            serial_number,
            current_version,
            last_seen,
            status
        ]

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[DeviceListItem]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
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
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    COLUMNS = [
        Column('ID', ID_WIDTH, ">"),
        Column('Project', PROJECT_NAME_WIDTH, "^"),
        Column('Version', VERSION_WIDTH, "^"),
        Column('FileName', FILENAME_WIDTH, "^"),
        Column('FileSize', FILESIZE_WIDTH, "^"),
        Column('Checksum', FILECHECKSUM_WIDTH, "^"),
        Column('Release notes', RELEASE_NOTES, "^"),
        Column('Channel', CHANNEL_WIDTH, "^"),
        Column('Status', STATUS_WIDTH, "^"),
        Column('Created At', DATE_WIDTH, "^"),
        Column('Updated At', DATE_WIDTH, "^")
    ]

    @classmethod
    def format(cls, firmware: Firmware) -> str:

        version = firmware.version if firmware.version else "-"
        filename = firmware.filename if firmware.filename else "-"
        file_size = str(firmware.file_size) if firmware.file_size else "-"
        channel = firmware.channel if firmware.channel else "-"
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

        values = [
            str(firmware.id),
            str(firmware.project_id),
            version,
            filename,
            file_size,
            firmware.checksum,
            firmware.release_notes,
            channel,
            status,
            created,
            updated
        ]

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[Firmware]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)

class FirmwareListItemFormatter:
    ID_WIDTH =  5
    PROJECT_NAME_WIDTH = 10
    VERSION_WIDTH = 32
    FILENAME_WIDTH = 32
    FILESIZE_WIDTH = 10
    CHANNEL_WIDTH = 10

    COLUMNS = [
        Column('ID', ID_WIDTH, ">"),
        Column('Project', PROJECT_NAME_WIDTH, "^"),
        Column('Version', VERSION_WIDTH, "^"),
        Column('FileName', FILENAME_WIDTH, "^"),
        Column('FileSize', FILESIZE_WIDTH, "^"),
        Column('Channel', CHANNEL_WIDTH, "^")
    ]

    @classmethod
    def format(cls, firmware: FirmwareListItem) -> str:

        version = firmware.version if firmware.version else "-"
        filename = firmware.filename if firmware.filename else "-"
        file_size = str(firmware.file_size) if firmware.file_size else "-"
        channel = firmware.channel if firmware.channel else "-"

        values = [
            str(firmware.id),
            firmware.project_name,
            version,
            filename,
            file_size,
            channel
        ]

        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[FirmwareListItem]) -> str:

        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
        ]

        for item in items:
            lines.extend(cls.format(item))

        return "\n".join(lines)