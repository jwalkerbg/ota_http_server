# db_sqlite_service.py

import sqlite3
from pathlib import Path
from datetime import datetime, UTC

from ota_http_server.core.config import Config
from ota_http_server.database.migration_sqlite3_runner import MigrationRunner
from ota_http_server.core.data_models import User, Project, Device, Firmware
from ota_http_server.core.data_models import AppPaths
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class UserHasProjectsError(Exception):
    pass

class UserNotFoundError(Exception):
    pass

class UserAlreadyEnabledError(Exception):
    pass

class UserAlreadyDisabledError(Exception):
    pass

class UserAlreadyExistsError(Exception):
    pass

class ProjectAlreadyExistsError(Exception):
    pass

class ProjectNotFoundError(Exception):
    pass

class ProjectAlreadyEnabledError(Exception):
    pass

class ProjectAlreadyDisabledError(Exception):
    pass

class DeviceAlreadyExistsError(Exception):
    pass

class DeviceNotFoundError(Exception):
    pass

class DeviceAlreadyEnabledError(Exception):
    pass

class DeviceAlreadyDisabledError(Exception):
    pass

class FirmwareAlreadyExistsError(Exception):
    pass

class FirmwareNotFoundError(Exception):
    pass

class FirmwareAlreadyEnabledError(Exception):
    pass

class FirmwareAlreadyDisabledError(Exception):
    pass

class DatabaseError(Exception):
    pass

class DatabaseSqliteService:
    def __init__(self, cfg:Config):
        self.cfg = cfg
        self.migration_runner = MigrationRunner(cfg)
        self.app_paths:AppPaths = self.cfg.config['parameters']['app_paths']

    def _connect(self):
        conn = sqlite3.connect(self.app_paths.database_sqlite)
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.cfg.config["parameters"]["trace_sql"]:
            conn.set_trace_callback(lambda sql: logger.debug("SQL: %s", sql))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        self.migration_runner.migrate_up()

    def migrate(self):
        self.migration_runner.migrate_up()

    def rollback(self):
        self.migration_runner.migrate_down()

    def add_user(self, name: str, email: str):
        logger.info('add_user executed')

    def add_user(self, user: User) -> User:
        """
        Add a new user to the database.

        Args:
            user: User dataclass instance. password_hash must already be generated.

        Returns:
            User object with assigned database id.

        Raises:
            UserAlreadyExistsError:
                If username or email already exists.
            DatabaseError:
                For unexpected database errors.
        """

        sql = """
            INSERT INTO users (
                username,
                password_hash,
                email,
                role,
                is_active,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    sql,
                    (
                        user.username,
                        user.password_hash,
                        user.email,
                        user.role,
                        1 if user.is_active else 0,
                        now.isoformat(),
                        now.isoformat(),
                    )
                )

                user.id = cursor.lastrowid
                user.created_at = now
                user.updated_at = now

                conn.commit()

                return user

        except sqlite3.IntegrityError as e:

            message = str(e)
            if "users.username" in message:
                raise UserAlreadyExistsError(
                    f"Username '{user.username}' already exists"
                ) from e
            if "users.email" in message:
                raise UserAlreadyExistsError(
                    f"Email '{user.email}' already exists"
                ) from e
            raise DatabaseError(
                f"Database integrity error while adding user: {message}"
            ) from e

        except sqlite3.Error as e:

            raise DatabaseError(
                f"Database error while adding user '{user.username}'"
            ) from e

    def _user_enable_disable(self, column: str, parameter: int | str, op: bool):

        if column not in ("id", "username"):
            raise ValueError(f"Invalid column '{column}'")

        if op:
            operation = "1"
            state = "0"
        else:
            operation = "0"
            state = "1"

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    f"""
                    UPDATE users
                    SET
                        is_active = {operation},
                        updated_at = ?
                    WHERE {column} = ?
                    AND is_active = {state}
                    """,
                    (
                        now.isoformat(),
                        parameter,
                    )
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.execute(
                    f"""
                    SELECT is_active
                    FROM users
                    WHERE {column} = ?
                    """,
                    (parameter,)
                )

                row = cursor.fetchone()

                if row is None:
                    raise UserNotFoundError(...)

            if op:
                raise UserAlreadyEnabledError(...)
            else:
                raise UserAlreadyDisabledError(...)

        except sqlite3.Error as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling user {column}={parameter}"
                ) from e
            else:
                raise DatabaseError(
                    f"Database error disabling user {column}={parameter}"
                ) from e


    def user_enable_by_id(self, user_id: int) -> None:
        return self._user_enable_disable("id", user_id, True)

    def user_enable_by_username(self, username: str) -> None:
        return self._user_enable_disable("username", username, True)

    def user_disable_by_id(self, user_id: int) -> None:
        return self._user_enable_disable("id", user_id, False)

    def user_disable_by_username(self, username: str) -> None:
        return self._user_enable_disable("username", username, False)

    def _row_to_user(self, row: sqlite3.Row) -> User:

        return User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            email=row["email"],
            role=row["role"],
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(row["created_at"])
                if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"])
                if row["updated_at"] else None,
        )

    def _user_get(self, column: str, parameter: int | str) -> User | None:

        if column not in ("id", "username"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    f"""
                    SELECT
                        id,
                        username,
                        password_hash,
                        email,
                        role,
                        is_active,
                        created_at,
                        updated_at
                    FROM users
                    WHERE {column} = ?
                    """,
                    (parameter,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_user(row)

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error retrieving user {column}={parameter}"
            ) from e

    def user_get_by_id(self, user_id: int) -> User | None:
        return self._user_get("id", user_id)

    def user_get_by_username(self, username: str) -> User | None:
        return self._user_get("username", username)

    def user_get_list(self) -> list[User]:
        """
        Get all users from database.

        Returns:
            List of User objects. Empty list if no users exist.
        """

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    SELECT
                        id,
                        username,
                        password_hash,
                        email,
                        role,
                        is_active,
                        created_at,
                        updated_at
                    FROM users
                    ORDER BY username
                    """
                )

                rows = cursor.fetchall()

                return [
                    self._row_to_user(row)
                    for row in rows
                ]

        except sqlite3.Error as e:
            raise DatabaseError(
                "Database error retrieving users"
            ) from e

    def _row_to_project(self, row: sqlite3.Row) -> Project:

            return Project(
                id=row["id"],
                name=row["name"],
                display_name=row["display_name"],
                description=row["description"],
                created_by=row["created_by"],
                is_active=bool(row["is_active"]),
                created_at=datetime.fromisoformat(row["created_at"])
                    if row["created_at"] else None,
                updated_at=datetime.fromisoformat(row["updated_at"])
                    if row["updated_at"] else None,
            )

    def add_project(self, project: Project) -> Project:

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    INSERT INTO projects
                    (
                        name,
                        display_name,
                        description,
                        created_by,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        project.name,
                        project.display_name,
                        project.description,
                        project.created_by,
                        int(project.is_active),
                        now.isoformat(),
                        None,
                    )
                )

                conn.commit()

                project.id = cursor.lastrowid
                project.created_at = now
                project.updated_at = None

                return project

        except sqlite3.IntegrityError as e:
            match e.sqlite_errorname:

                case "SQLITE_CONSTRAINT_UNIQUE":
                    raise ProjectAlreadyExistsError(
                        f"Project '{project.name}' already exists"
                    ) from e
                case "SQLITE_CONSTRAINT_FOREIGNKEY":
                    raise UserNotFoundError(
                        f"Database Integrity violation: Project with id={project.created_by} does not exist"
                    ) from e

                case _:
                    raise DatabaseError(
                        f"Database integrity error creating project '{project.name}': {str(e)}"
                    ) from e
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error creating project '{project.name}'"
            ) from e

    def _project_enable_disable(self, column: str, parameter: int | str, op: bool):

        if column not in ("id", "name"):
            raise ValueError(f"Invalid column '{column}'")

        if op:
            operation = "1"
            state = "0"
        else:
            operation = "0"
            state = "1"

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    f"""
                    UPDATE projects
                    SET
                        is_active = {operation},
                        updated_at = ?
                    WHERE {column} = ?
                    AND is_active = {state}
                    """,
                    (
                        now.isoformat(),
                        parameter,
                    )
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.execute(
                    f"""
                    SELECT is_active
                    FROM projects
                    WHERE {column} = ?
                    """,
                    (parameter,)
                )

                row = cursor.fetchone()

                if row is None:
                    raise ProjectNotFoundError(...)

            if op:
                raise ProjectAlreadyEnabledError(...)
            else:
                raise ProjectAlreadyDisabledError(...)

        except sqlite3.Error as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling project {column}={parameter}"
                ) from e
            else:
                raise DatabaseError(
                    f"Database error disabling project {column}={parameter}"
                ) from e

    def enable_project_by_id(self, id: int) -> None:
        return self._project_enable_disable("id", id, True)

    def enable_project_by_name(self, name: str) -> None:
        return self._project_enable_disable("name", name, True)

    def disable_project_by_id(self, id: int) -> None:
        return self._project_enable_disable("id", id, False)

    def disable_project_by_name(self, name: str) -> Project |None:
        return self._project_enable_disable("name", name, False)

    def _project_get(self, column: str, parameter: int | str) -> Project | None:

        if column not in ("id", "name"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    f"""
                    SELECT
                        id,
                        name,
                        display_name,
                        description,
                        created_by,
                        is_active,
                        created_at,
                        updated_at
                    FROM projects
                    WHERE {column} = ?
                    """,
                    (parameter,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_project(row)

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error retrieving project {column}={parameter}"
            ) from e

    def get_project_by_id(self, id: int) -> Project | None:
        return self._project_get("id", id)

    def get_project_by_name(self, name: str) -> Project | None:
        return self._project_get("name", name)

    def project_get_list(self) -> list[Project]:

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    SELECT
                        id,
                        name,
                        display_name,
                        description,
                        created_by,
                        is_active,
                        created_at,
                        updated_at
                    FROM projects
                    ORDER BY name
                    """
                )

                rows = cursor.fetchall()

                return [
                    self._row_to_project(row)
                    for row in rows
                ]

        except sqlite3.Error as e:
            raise DatabaseError(
                "Database error retrieving projects"
            ) from e

    def _row_to_device(self, row: sqlite3.Row) -> Device:

            return Device(
                id=row["id"],
                uuid=row["uuid"],
                project_id=row["project_id"],
                model=row["model"],
                serial_number=row["serial_number"]
                    if row["serial_number"] else "",
                current_version=row["current_version"]
                    if row["current_version"] else "",
                last_seen=datetime.fromisoformat(row["last_seen"])
                    if row["last_seen"] else None,
                is_active=bool(row["is_active"]),
                created_at=datetime.fromisoformat(row["created_at"])
                    if row["created_at"] else None,
                updated_at=datetime.fromisoformat(row["updated_at"])
                    if row["updated_at"] else None,
            )

    def add_device(self, device: Device) -> Device:

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    INSERT INTO devices
                    (
                        id,
                        uuid,
                        project_id,
                        model,
                        serial_number,
                        current_version,
                        last_seen,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device.id,
                        device.uuid,
                        device.project_id,
                        device.model,
                        device.serial_number,
                        device.current_version,
                        None,
                        int(device.is_active),
                        now.isoformat(),
                        None
                    )
                )

                conn.commit()

                device.id = cursor.lastrowid
                device.created_at = now
                device.updated_at = None

                return device

        except sqlite3.IntegrityError as e:
            match e.sqlite_errorname:

                case "SQLITE_CONSTRAINT_UNIQUE":
                    raise DeviceAlreadyExistsError(
                        f"Device '{device.name}' already exists"
                    ) from e
                case "SQLITE_CONSTRAINT_FOREIGNKEY":
                    raise UserNotFoundError(
                        f"Database Integrity violation: Project with id={device.project_id} does not exist"
                    ) from e

                case _:
                    raise DatabaseError(
                        f"Database integrity error creating device '{device.uuid}': {str(e)}"
                    ) from e
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error creating device '{device.uuid}'"
            ) from e

    def _device_enable_disable(self, column: str, parameter: int | str, op: bool):

        if column not in ("id", "uuid"):
            raise ValueError(f"Invalid column '{column}'")

        if op:
            operation = "1"
            state = "0"
        else:
            operation = "0"
            state = "1"

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    f"""
                    UPDATE devices
                    SET
                        is_active = {operation},
                        updated_at = ?
                    WHERE {column} = ?
                    AND is_active = {state}
                    """,
                    (
                        now.isoformat(),
                        parameter,
                    )
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.execute(
                    f"""
                    SELECT is_active
                    FROM devices
                    WHERE {column} = ?
                    """,
                    (parameter,)
                )

                row = cursor.fetchone()

                if row is None:
                    raise DeviceNotFoundError(...)

            if op:
                raise DeviceAlreadyEnabledError(...)
            else:
                raise DeviceAlreadyDisabledError(...)

        except sqlite3.Error as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling device {column}={parameter}"
                ) from e
            else:
                raise DatabaseError(
                    f"Database error disabling device {column}={parameter}"
                ) from e

    def enable_device_by_id(self, id: int) -> None:
        return self._device_enable_disable("id", id, True)

    def enable_device_by_name(self, name: str) -> None:
        return self._device_enable_disable("uuid", name, True)

    def disable_device_by_id(self, id: int) -> None:
        return self._device_enable_disable("id", id, False)

    def disable_device_by_name(self, name: str) -> None:
        return self._device_enable_disable("uuid", name, False)

    def _device_get(self, column: str, parameter: int | str) -> Device | None:

        if column not in ("id", "uuid"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    f"""
                    SELECT
                        id,
                        uuid,
                        project_id,
                        model,
                        serial_number,
                        current_version,
                        last_seen,
                        is_active,
                        created_at,
                        updated_at
                    FROM devices
                    WHERE {column} = ?
                    """,
                    (parameter,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_device(row)

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error retrieving device {column}={parameter}"
            ) from e

    def get_device_by_id(self, id: int) -> Device | None:
        return self._device_get("id", id)

    def get_device_by_name(self, name: str) -> Device | None:
        return self._device_get("uuid", name)

    def device_get_list(self) -> list[Device]:

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    SELECT
                        id,
                        uuid,
                        project_id,
                        model,
                        serial_number,
                        current_version,
                        last_seen,
                        is_active,
                        created_at,
                        updated_at
                    FROM devices
                    ORDER BY id
                    """
                )

                rows = cursor.fetchall()

                return [
                    self._row_to_device(row)
                    for row in rows
                ]

        except sqlite3.Error as e:
            raise DatabaseError(
                "Database error retrieving devices"
            ) from e

    def _row_to_firmware(self, row: sqlite3.Row) -> Firmware:

            return Firmware(
                id=row["id"],
                project_id=row["project_id"],
                version=row["version"],
                filename=row["filename"]
                    if row["filename"] else "",
                file_size=row["file_size"]
                    if row["file_size"] else 0,
                checksum=row["checksum"]
                    if row["checksum"] else "",
                release_notes = row["release_notes"]
                    if row["release_notes"] else "",
                channel = row["channel"],
                is_active=bool(row["is_active"]),
                created_at=datetime.fromisoformat(row["created_at"])
                    if row["created_at"] else None,
                updated_at=datetime.fromisoformat(row["updated_at"])
                    if row["updated_at"] else None,
            )

    def add_firmware(self, firmware: Firmware) -> Firmware:

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    INSERT INTO firmware
                    (
                        id,
                        project_id,
                        version,
                        filename,
                        file_size,
                        checksum,
                        release_notes,
                        channel,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        firmware.id,
                        firmware.project_id,
                        firmware.version,
                        firmware.filename,
                        firmware.file_size,
                        firmware.checksum,
                        firmware.release_notes,
                        firmware.channel,
                        int(firmware.is_active),
                        now.isoformat(),
                        None
                    )
                )

                conn.commit()

                firmware.id = cursor.lastrowid
                firmware.created_at = now
                firmware.updated_at = None

                return firmware

        except sqlite3.IntegrityError as e:
            match e.sqlite_errorname:

                case "SQLITE_CONSTRAINT_UNIQUE":
                    raise FirmwareAlreadyExistsError(
                        f"Firmware '{firmware.id}' already exists"
                    ) from e
                case "SQLITE_CONSTRAINT_FOREIGNKEY":
                    raise ProjectNotFoundError(
                        f"Database Integrity violation: Project with id={firmware.project_id} does not exist"
                    ) from e

                case _:
                    raise DatabaseError(
                        f"Database integrity error creating firmware '{firmware.id}': {str(e)}"
                    ) from e
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error creating firmware '{firmware.uuid}'"
            ) from e

    def _firmware_enable_disable(
            self,
            columns: tuple[str, ...],
            parameters: tuple[int | str, ...],
            op: bool
        ):

        allowed_columns = {
            "id",
            "project_id",
            "version",
        }

        if not columns:
            raise ValueError("At least one column is required")

        if len(columns) != len(parameters):
            raise ValueError(
                "Number of columns must match number of parameters"
            )

        lookup = ", ".join(
            f"{column}={parameter}"
            for column, parameter in zip(columns, parameters)
        )

        if op:
            operation = "1"
            state = "0"
        else:
            operation = "0"
            state = "1"

        where_clause = " AND ".join(
            f"{column} = ?" for column in columns
        )

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    f"""
                    UPDATE firmware
                    SET
                        is_active = {operation},
                        updated_at = ?
                    WHERE {where_clause}
                    AND is_active = {state}
                    """,
                    (
                        now.isoformat(),
                        *parameters,
                    )
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.execute(
                    f"""
                    SELECT is_active
                    FROM firmware
                    WHERE {where_clause}
                    """,
                    parameters,
                )

                row = cursor.fetchone()

                if row is None:
                    raise FirmwareNotFoundError(
                        f"Firmware {lookup} not found"
                    )

            if op:
                raise FirmwareAlreadyEnabledError(
                    f"Firmware {lookup} is already enabled"
                )
            else:
                raise FirmwareAlreadyDisabledError(
                    f"Firmware {lookup} is already disabled"
                )

        except sqlite3.Error as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling firmware {lookup}"
                ) from e
            else:
                raise DatabaseError(
                    f"Database error disabling firmware {lookup}"
                ) from e

    def enable_firmware_by_id(self, id: int) -> None:
        self._firmware_enable_disable(("id",), (id,), True)

    def enable_firmware_by_project_version(self, project_id: int, version: str) -> None:
        self._firmware_enable_disable(("project_id", "version"), (project_id, version), True)

    def disable_firmware_by_id(self, id: int) -> None:
        self._firmware_enable_disable(("id",), (id,), False)

    def disable_firmware_by_project_version(self, project_id: int, version: str) -> None:
        self._firmware_enable_disable(("project_id", "version"), (project_id, version), False)

    def _firmware_get(
            self,
            columns: tuple[str, ...],
            parameters: tuple[int | str, ...],
        ) -> Firmware | None:

        allowed_columns = {
            "id",
            "project_id",
            "version",
        }

        if not columns:
            raise ValueError("At least one column is required")

        if len(columns) != len(parameters):
            raise ValueError(
                "Number of columns must match number of parameters"
            )

        where_clause = " AND ".join(
            f"{column} = ?" for column in columns
        )

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    f"""
                    SELECT
                        id,
                        project_id,
                        version,
                        filename,
                        file_size,
                        checksum,
                        release_notes,
                        channel,
                        is_active,
                        created_at,
                        updated_at
                    FROM firmware
                    WHERE {where_clause}
                    """,
                    parameters,
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_firmware(row)

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error retrieving firmware {column}={parameter}"
            ) from e

    def firmware_get_by_id(
        self,
        firmware_id: int,
    ) -> Firmware | None:

        return self._firmware_get(
            ("id",),
            (firmware_id,),
        )

    def firmware_get_by_project_version(
        self,
        project_id: int,
        version: str,
    ) -> Firmware | None:

        return self._firmware_get(
            ("project_id", "version"),
            (project_id, version),
        )

    def firmware_get_list(self) -> list[Firmware]:

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    SELECT
                        id,
                        project_id,
                        version,
                        filename,
                        file_size,
                        checksum,
                        release_notes,
                        channel,
                        is_active,
                        created_at,
                        updated_at
                    FROM firmware
                    ORDER BY project_id, id
                    """
                )

                rows = cursor.fetchall()

                return [
                    self._row_to_firmware(row)
                    for row in rows
                ]

        except sqlite3.Error as e:
            raise DatabaseError(
                "Database error retrieving firmware"
            ) from e
