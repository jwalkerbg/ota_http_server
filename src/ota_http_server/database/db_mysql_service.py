# database/db_mysql_service.py

from datetime import UTC, datetime
from typing import Any, NoReturn

import mysql.connector
from mysql.connector import Error as MySQLError

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import (
    Device,
    DeviceListItem,
    Firmware,
    FirmwareDeleteInfo,
    FirmwareListItem,
    Project,
    ProjectListItem,
    Target,
    User,
)
from ota_http_server.database.mysql_sql_tracing import (
    is_sql_tracing_enabled,
    with_mysql_sql_tracing,
)
from ota_http_server.database.migration_mysql_runner import MigrationMySQLRunner
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


class TargetAlreadyExistsError(Exception):
    pass


class TargetNotFoundError(Exception):
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


class DatabaseMySQLService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.migration_runner = MigrationMySQLRunner(cfg)

    def _connect(self):
        db_config = self.cfg.config["database"]["mysql"]
        conn = mysql.connector.connect(
            host=db_config["dbhost"],
            port=db_config["dbport"],
            database=db_config["database"],
            user=db_config["dbuser"],
            password=db_config["dbpassword"],
            autocommit=False,
        )
        sql_trace_enabled = is_sql_tracing_enabled(
            self.cfg.config["parameters"]["trace_sql"],
            db_config["dbecho"],
        )
        return with_mysql_sql_tracing(conn, logger, sql_trace_enabled)

    @staticmethod
    def _as_datetime(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(str(value))

    def _unsupported(self, action: str) -> NoReturn:
        raise NotImplementedError(
            f"MySQL database support is not implemented for {action}"
        )

    def init_db(self) -> None:
        self.migration_runner.migrate_up()

    def migrate(self) -> None:
        self.migration_runner.migrate_up()

    def rollback(self) -> None:
        self.migration_runner.migrate_down()

    def _row_to_user(self, row: dict[str, Any]) -> User:
        return User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            email=row["email"],
            role=row["role"],
            is_active=bool(row["is_active"]),
            created_at=self._as_datetime(row["created_at"]),
            updated_at=self._as_datetime(row["updated_at"]),
        )

    def user_add(self, user: User) -> User:
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
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    sql,
                    (
                        user.username,
                        user.password_hash,
                        user.email,
                        user.role,
                        1 if user.is_active else 0,
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
                user.id = cursor.lastrowid
                user.created_at = now
                user.updated_at = now
                conn.commit()
                return user
        except mysql.connector.IntegrityError as e:
            message = str(e)
            if "users.username" in message or "username" in message:
                raise UserAlreadyExistsError(
                    f"Username '{user.username}' already exists"
                ) from e
            if "users.email" in message or "email" in message:
                raise UserAlreadyExistsError(
                    f"Email '{user.email}' already exists"
                ) from e
            raise DatabaseError(
                f"Database integrity error while adding user: {message}"
            ) from e
        except MySQLError as e:
            raise DatabaseError(
                f"Database error while adding user '{user.username}'"
            ) from e

    def _user_enable_disable(self, column: str, parameter: int | str, op: bool):
        if column not in ("id", "username"):
            raise ValueError(f"Invalid column '{column}'")

        new_state = 1 if op else 0
        old_state = 0 if op else 1
        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    UPDATE users
                    SET
                        is_active = %s,
                        updated_at = %s
                    WHERE {column} = %s
                    AND is_active = %s
                    """,
                    (new_state, now.isoformat(), parameter, old_state),
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"SELECT is_active FROM users WHERE {column} = %s",
                    (parameter,),
                )
                row = cursor.fetchone()

                if row is None:
                    raise UserNotFoundError(f"User {column}={parameter} not found")

            if op:
                raise UserAlreadyEnabledError(f"User {column}={parameter} is already enabled")
            raise UserAlreadyDisabledError(f"User {column}={parameter} is already disabled")

        except MySQLError as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling user {column}={parameter}"
                ) from e
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

    def _user_get(self, column: str, parameter: int | str) -> User | None:
        if column not in ("id", "username"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
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
                    WHERE {column} = %s
                    """,
                    (parameter,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_user(row)
        except MySQLError as e:
            raise DatabaseError(
                f"Database error retrieving user {column}={parameter}"
            ) from e

    def user_get_by_id(self, user_id: int) -> User | None:
        return self._user_get("id", user_id)

    def user_get_by_username(self, username: str) -> User | None:
        return self._user_get("username", username)

    def user_is_active(self, user_id: int) -> bool:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT is_active FROM users WHERE id = %s",
                    (user_id,),
                )
                row = cursor.fetchone()
                return bool(row["is_active"]) if row is not None else False
        except MySQLError as e:
            raise DatabaseError(
                f"Database error checking whether user {user_id} is active"
            ) from e

    def user_get_list(self, is_active: bool | None = None) -> list[User]:
        try:
            with self._connect() as conn:
                query = """
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
                """
                params: tuple[Any, ...] = ()
                if is_active is not None:
                    query += " WHERE is_active = %s"
                    params = (1 if is_active else 0,)
                query += " ORDER BY username"

                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [self._row_to_user(row) for row in rows]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving user list") from e

    def user_get_record(self, is_active: bool | None = None) -> list[User]:
        return self.user_get_list(is_active=is_active)

    def _row_to_project(self, row: dict[str, Any]) -> Project:
        return Project(
            id=row["id"],
            name=row["name"],
            display_name=row["display_name"],
            description=row["description"],
            created_by=row["created_by"],
            is_active=bool(row["is_active"]),
            created_at=self._as_datetime(row["created_at"]),
            updated_at=self._as_datetime(row["updated_at"]),
        )

    def project_add(self, project: Project) -> Project:
        now = datetime.now(UTC)
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO projects (
                        name,
                        display_name,
                        description,
                        created_by,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        project.name,
                        project.display_name,
                        project.description,
                        project.created_by,
                        1 if project.is_active else 0,
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )
                project.id = cursor.lastrowid
                project.created_at = now
                project.updated_at = now
                conn.commit()
                return project
        except mysql.connector.IntegrityError as e:
            message = str(e)
            if "projects.name" in message or "name" in message:
                raise ProjectAlreadyExistsError(
                    f"Project '{project.name}' already exists"
                ) from e
            if "projects.created_by" in message or "created_by" in message:
                raise ProjectNotFoundError(
                    f"Project creation failed because user id={project.created_by} does not exist"
                ) from e
            raise DatabaseError(
                f"Database integrity error creating project '{project.name}': {message}"
            ) from e
        except MySQLError as e:
            raise DatabaseError(
                f"Database error creating project '{project.name}'"
            ) from e

    def _project_enable_disable(self, column: str, parameter: int | str, op: bool):
        if column not in ("id", "name"):
            raise ValueError(f"Invalid column '{column}'")

        new_state = 1 if op else 0
        old_state = 0 if op else 1
        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    UPDATE projects
                    SET
                        is_active = %s,
                        updated_at = %s
                    WHERE {column} = %s
                    AND is_active = %s
                    """,
                    (new_state, now.isoformat(), parameter, old_state),
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"SELECT is_active FROM projects WHERE {column} = %s",
                    (parameter,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ProjectNotFoundError(f"Project {column}={parameter} not found")

            if op:
                raise ProjectAlreadyEnabledError(f"Project {column}={parameter} is already enabled")
            raise ProjectAlreadyDisabledError(f"Project {column}={parameter} is already disabled")
        except MySQLError as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling project {column}={parameter}"
                ) from e
            raise DatabaseError(
                f"Database error disabling project {column}={parameter}"
            ) from e

    def project_enable_by_id(self, id: int) -> None:
        return self._project_enable_disable("id", id, True)

    def project_enable_by_name(self, name: str) -> None:
        return self._project_enable_disable("name", name, True)

    def project_disable_by_id(self, id: int) -> None:
        return self._project_enable_disable("id", id, False)

    def project_disable_by_name(self, name: str) -> None:
        return self._project_enable_disable("name", name, False)

    def _project_get(self, column: str, parameter: int | str) -> Project | None:
        if column not in ("id", "name"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
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
                    WHERE {column} = %s
                    """,
                    (parameter,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_project(row)
        except MySQLError as e:
            raise DatabaseError(
                f"Database error retrieving project {column}={parameter}"
            ) from e

    def project_get_by_id(self, id: int) -> Project | None:
        return self._project_get("id", id)

    def project_get_by_name(self, name: str) -> Project | None:
        return self._project_get("name", name)

    def project_is_active(self, project_id: int) -> bool:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT is_active FROM projects WHERE id = %s",
                    (project_id,),
                )
                row = cursor.fetchone()
                return bool(row["is_active"]) if row is not None else False
        except MySQLError as e:
            raise DatabaseError(
                f"Database error checking whether project {project_id} is active"
            ) from e

    def project_get_record(self) -> list[Project]:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
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
                return [self._row_to_project(row) for row in cursor.fetchall()]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving projects") from e

    def project_get_list(self) -> list[ProjectListItem]:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    SELECT
                        projects.id,
                        projects.name,
                        projects.display_name,
                        projects.description,
                        users.username AS created_by_username,
                        projects.is_active
                    FROM projects
                    JOIN users ON users.id = projects.created_by
                    ORDER BY projects.name
                    """
                )
                rows = cursor.fetchall()
                return [
                    ProjectListItem(
                        id=row["id"],
                        name=row["name"],
                        display_name=row["display_name"],
                        description=row["description"],
                        created_by_username=row["created_by_username"],
                        is_active=bool(row["is_active"]),
                    )
                    for row in rows
                ]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving project list") from e

    def _row_to_target(self, row: dict[str, Any]) -> Target:
        return Target(
            id=row["id"],
            name=row["name"],
        )

    def target_add(self, target: Target) -> Target:
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO targets (name)
                    VALUES (%s)
                    """,
                    (target.name,),
                )
                conn.commit()
                target.id = cursor.lastrowid
                return target
        except mysql.connector.IntegrityError as e:
            raise TargetAlreadyExistsError(
                f"Target '{target.name}' already exists"
            ) from e
        except MySQLError as e:
            raise DatabaseError(
                f"Database error creating target '{target.name}'"
            ) from e

    def _target_get(self, column: str, parameter: int | str) -> Target | None:
        if column not in ("id", "name"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT id, name
                    FROM targets
                    WHERE {column} = %s
                    """,
                    (parameter,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_target(row)
        except MySQLError as e:
            raise DatabaseError(
                f"Database error retrieving target {column}={parameter}"
            ) from e

    def target_get_by_id(self, id: int) -> Target | None:
        return self._target_get("id", id)

    def target_get_by_name(self, name: str) -> Target | None:
        return self._target_get("name", name)

    def target_get_list(self) -> list[Target]:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    SELECT id, name
                    FROM targets
                    ORDER BY name, id
                    """
                )
                return [self._row_to_target(row) for row in cursor.fetchall()]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving targets") from e

    def _row_to_device(self, row: dict[str, Any]) -> Device:
        return Device(
            id=row["id"],
            uuid=row["uuid"],
            project_id=row["project_id"],
            target_id=row["target_id"],
            model=row["model"],
            serial_number=row["serial_number"],
            current_version=row["current_version"],
            last_seen=self._as_datetime(row["last_seen"]),
            is_active=bool(row["is_active"]),
            created_at=self._as_datetime(row["created_at"]),
            updated_at=self._as_datetime(row["updated_at"]),
        )

    def device_add(self, device: Device) -> Device:
        now = datetime.now(UTC)
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO devices (
                        uuid,
                        project_id,
                        target_id,
                        model,
                        serial_number,
                        current_version,
                        last_seen,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        device.uuid,
                        device.project_id,
                        device.target_id,
                        device.model,
                        device.serial_number,
                        device.current_version,
                        None,
                        int(device.is_active),
                        now.isoformat(),
                        None,
                    ),
                )
                conn.commit()
                device.id = cursor.lastrowid
                device.created_at = now
                device.updated_at = None
                return device
        except mysql.connector.IntegrityError as e:
            message = str(e)
            if "devices.uuid" in message or "uuid" in message:
                raise DeviceAlreadyExistsError(
                    f"Device '{device.uuid}' already exists"
                ) from e
            if "project_id" in message or "target_id" in message:
                raise TargetNotFoundError(
                    f"Database integrity violation: Project id={device.project_id} or target id={device.target_id} does not exist"
                ) from e
            raise DatabaseError(
                f"Database integrity error creating device '{device.uuid}': {message}"
            ) from e
        except MySQLError as e:
            raise DatabaseError(
                f"Database error creating device '{device.uuid}'"
            ) from e

    def _device_enable_disable(self, column: str, parameter: int | str, op: bool):
        if column not in ("id", "uuid"):
            raise ValueError(f"Invalid column '{column}'")

        new_state = 1 if op else 0
        old_state = 0 if op else 1
        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    UPDATE devices
                    SET
                        is_active = %s,
                        updated_at = %s
                    WHERE {column} = %s
                    AND is_active = %s
                    """,
                    (new_state, now.isoformat(), parameter, old_state),
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"SELECT is_active FROM devices WHERE {column} = %s",
                    (parameter,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise DeviceNotFoundError(f"Device {column}={parameter} not found")

            if op:
                raise DeviceAlreadyEnabledError(f"Device {column}={parameter} is already enabled")
            raise DeviceAlreadyDisabledError(f"Device {column}={parameter} is already disabled")
        except MySQLError as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling device {column}={parameter}"
                ) from e
            raise DatabaseError(
                f"Database error disabling device {column}={parameter}"
            ) from e

    def device_enable_by_id(self, id: int) -> None:
        return self._device_enable_disable("id", id, True)

    def device_enable_by_name(self, name: str) -> None:
        return self._device_enable_disable("uuid", name, True)

    def device_disable_by_id(self, id: int) -> None:
        return self._device_enable_disable("id", id, False)

    def device_disable_by_name(self, name: str) -> None:
        return self._device_enable_disable("uuid", name, False)

    def _device_change_target(self, column: str, parameter: int | str, target_id: int) -> None:
        if column not in ("id", "uuid"):
            raise ValueError(f"Invalid column '{column}'")

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT id FROM targets WHERE id = %s",
                    (target_id,),
                )
                if cursor.fetchone() is None:
                    raise TargetNotFoundError(f"Target id={target_id} not found")

                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    UPDATE devices
                    SET
                        target_id = %s,
                        updated_at = %s
                    WHERE {column} = %s
                    """,
                    (target_id, now.isoformat(), parameter),
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                raise DeviceNotFoundError(f"Device {column}={parameter} not found")
        except MySQLError as e:
            raise DatabaseError(
                f"Database error changing target for device {column}={parameter}"
            ) from e

    def device_change_target_by_id(self, id: int, target_id: int) -> None:
        self._device_change_target("id", id, target_id)

    def device_change_target_by_name(self, name: str, target_id: int) -> None:
        self._device_change_target("uuid", name, target_id)

    def _device_get(self, column: str, parameter: int | str) -> Device | None:
        if column not in ("id", "uuid"):
            raise ValueError(f"Invalid column '{column}'")

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT
                        id,
                        uuid,
                        project_id,
                        target_id,
                        model,
                        serial_number,
                        current_version,
                        last_seen,
                        is_active,
                        created_at,
                        updated_at
                    FROM devices
                    WHERE {column} = %s
                    """,
                    (parameter,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_device(row)
        except MySQLError as e:
            raise DatabaseError(
                f"Database error retrieving device {column}={parameter}"
            ) from e

    def device_get_by_id(self, id: int) -> Device | None:
        return self._device_get("id", id)

    def device_get_by_name(self, name: str) -> Device | None:
        return self._device_get("uuid", name)

    def device_is_active(self, device_id: int) -> bool:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT is_active FROM devices WHERE id = %s",
                    (device_id,),
                )
                row = cursor.fetchone()
                return bool(row["is_active"]) if row is not None else False
        except MySQLError as e:
            raise DatabaseError(
                f"Database error checking whether device {device_id} is active"
            ) from e

    def _build_device_filters(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> tuple[str, tuple[object, ...]]:
        filters: list[str] = []
        params: list[object] = []
        if is_active is not None:
            filters.append("devices.is_active = %s")
            params.append(1 if is_active else 0)
        if project_id is not None:
            filters.append("devices.project_id = %s")
            params.append(project_id)
        where_clause = ""
        if filters:
            where_clause = " WHERE " + " AND ".join(filters)
        return where_clause, tuple(params)

    def device_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Device]:
        try:
            with self._connect() as conn:
                where_clause, params = self._build_device_filters(
                    is_active=is_active,
                    project_id=project_id,
                )
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT
                        id,
                        uuid,
                        project_id,
                        target_id,
                        model,
                        serial_number,
                        current_version,
                        last_seen,
                        is_active,
                        created_at,
                        updated_at
                    FROM devices
                    {where_clause}
                    ORDER BY project_id, id
                    """,
                    params,
                )
                return [self._row_to_device(row) for row in cursor.fetchall()]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving devices") from e

    def device_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[DeviceListItem]:
        try:
            with self._connect() as conn:
                where_clause, params = self._build_device_filters(
                    is_active=is_active,
                    project_id=project_id,
                )
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT
                        devices.id,
                        devices.uuid AS uuid,
                        projects.name AS project_name,
                        targets.name AS target_name,
                        devices.model,
                        devices.serial_number,
                        devices.current_version,
                        devices.last_seen,
                        devices.is_active
                    FROM devices
                    JOIN projects ON projects.id = devices.project_id
                    JOIN targets ON targets.id = devices.target_id
                    {where_clause}
                    ORDER BY projects.name, devices.id
                    """,
                    params,
                )
                rows = cursor.fetchall()
                return [
                    DeviceListItem(
                        id=row["id"],
                        uuid=row["uuid"],
                        project_name=row["project_name"],
                        target_name=row["target_name"],
                        model=row["model"],
                        serial_number=row["serial_number"],
                        current_version=row["current_version"],
                        last_seen=self._as_datetime(row["last_seen"]),
                        is_active=bool(row["is_active"]),
                    )
                    for row in rows
                ]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving device list") from e

    def _row_to_firmware(self, row: dict[str, Any]) -> Firmware:
        return Firmware(
            id=row["id"],
            project_id=row["project_id"],
            target_id=row["target_id"],
            version=row["version"],
            filename=row["filename"],
            file_size=row["file_size"],
            checksum=row["checksum"],
            release_notes=row["release_notes"],
            channel=row["channel"],
            is_active=bool(row["is_active"]),
            created_at=self._as_datetime(row["created_at"]),
            updated_at=self._as_datetime(row["updated_at"]),
        )

    def _row_to_firmware_list(self, row: dict[str, Any]) -> FirmwareListItem:
        return FirmwareListItem(
            id=row["id"],
            project_name=row["project_name"],
            target_name=row["target_name"],
            version=row["version"],
            filename=row["filename"],
            file_size=row["file_size"],
            channel=row["channel"],
        )

    def firmware_add(self, firmware: Firmware) -> Firmware:
        now = datetime.now(UTC)
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO firmware (
                        project_id,
                        target_id,
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
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        firmware.project_id,
                        firmware.target_id,
                        firmware.version,
                        firmware.filename,
                        firmware.file_size,
                        firmware.checksum,
                        firmware.release_notes,
                        firmware.channel,
                        int(firmware.is_active),
                        now.isoformat(),
                        None,
                    ),
                )
                conn.commit()
                firmware.id = cursor.lastrowid
                firmware.created_at = now
                firmware.updated_at = None
                return firmware
        except mysql.connector.IntegrityError as e:
            message = str(e)
            if "uq_firmware_project_version_target" in message or "Duplicate entry" in message:
                raise FirmwareAlreadyExistsError(
                    f"Firmware '{firmware.version}' already exists"
                ) from e
            if "project_id" in message or "target_id" in message:
                raise TargetNotFoundError(
                    f"Database integrity violation: Project id={firmware.project_id} or target id={firmware.target_id} does not exist"
                ) from e
            raise DatabaseError(
                f"Database integrity error creating firmware '{firmware.version}': {message}"
            ) from e
        except MySQLError as e:
            raise DatabaseError(
                f"Database error creating firmware '{firmware.version}'"
            ) from e

    def firmware_replace(self, firmware_id: int, filename: str, file_size: int, checksum: str) -> Firmware:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    SELECT
                        id,
                        project_id,
                        target_id,
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
                    WHERE id = %s
                    """,
                    (firmware_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise FirmwareNotFoundError(f"Firmware id={firmware_id} not found")

                updated = self._row_to_firmware(row)
                updated.filename = filename
                updated.file_size = file_size
                updated.checksum = checksum
                updated.updated_at = datetime.now(UTC)

                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE firmware
                    SET
                        filename = %s,
                        file_size = %s,
                        checksum = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (
                        updated.filename,
                        updated.file_size,
                        updated.checksum,
                        updated.updated_at.isoformat(),
                        firmware_id,
                    ),
                )
                conn.commit()
                return updated
        except MySQLError as e:
            raise DatabaseError(
                f"Database error updating firmware '{firmware_id}'"
            ) from e

    def _row_to_firmware_delete_info(self, row: dict[str, Any]) -> FirmwareDeleteInfo:
        return FirmwareDeleteInfo(
            id=row["id"],
            project_name=row["project_name"],
            filename=row["filename"],
        )

    def firmware_delete_by_id(self, firmware_id: int) -> FirmwareDeleteInfo:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    DELETE FROM firmware
                    WHERE id = %s
                    RETURNING
                        id,
                        filename,
                        (
                            SELECT name
                            FROM projects
                            WHERE projects.id = firmware.project_id
                        ) AS project_name
                    """,
                    (firmware_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise FirmwareNotFoundError(f"Firmware id={firmware_id} not found")
                conn.commit()
                return self._row_to_firmware_delete_info(row)
        except MySQLError as e:
            raise DatabaseError(
                f"Database error deleting firmware '{firmware_id}'"
            ) from e

    def firmware_delete_by_project_version(
        self,
        project_id: int,
        version: str,
    ) -> FirmwareDeleteInfo:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    DELETE FROM firmware
                    WHERE project_id = %s
                    AND version = %s
                    RETURNING
                        id,
                        filename,
                        (
                            SELECT name
                            FROM projects
                            WHERE projects.id = firmware.project_id
                        ) AS project_name
                    """,
                    (project_id, version),
                )
                row = cursor.fetchone()
                if row is None:
                    raise FirmwareNotFoundError(
                        f"Firmware project_id={project_id}, version={version} not found"
                    )
                conn.commit()
                return self._row_to_firmware_delete_info(row)
        except MySQLError as e:
            raise DatabaseError(
                f"Database error deleting firmware project_id={project_id}, version={version}"
            ) from e

    def _firmware_enable_disable(
        self,
        columns: tuple[str, ...],
        parameters: tuple[int | str, ...],
        op: bool,
    ):
        if not columns:
            raise ValueError("At least one column is required")
        if len(columns) != len(parameters):
            raise ValueError("Number of columns must match number of parameters")

        lookup = ", ".join(f"{column}={parameter}" for column, parameter in zip(columns, parameters))
        new_state = 1 if op else 0
        old_state = 0 if op else 1
        where_clause = " AND ".join(f"{column} = %s" for column in columns)
        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    UPDATE firmware
                    SET
                        is_active = %s,
                        updated_at = %s
                    WHERE {where_clause}
                    AND is_active = %s
                    """,
                    (new_state, now.isoformat(), *parameters, old_state),
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"SELECT is_active FROM firmware WHERE {where_clause}",
                    parameters,
                )
                row = cursor.fetchone()
                if row is None:
                    raise FirmwareNotFoundError(f"Firmware {lookup} not found")

            if op:
                raise FirmwareAlreadyEnabledError(f"Firmware {lookup} is already enabled")
            raise FirmwareAlreadyDisabledError(f"Firmware {lookup} is already disabled")
        except MySQLError as e:
            if op:
                raise DatabaseError(
                    f"Database error enabling firmware {lookup}"
                ) from e
            raise DatabaseError(
                f"Database error disabling firmware {lookup}"
            ) from e

    def firmware_enable_by_id(self, id: int) -> None:
        self._firmware_enable_disable(("id",), (id,), True)

    def firmware_enable_by_project_version(self, project_id: int, version: str) -> None:
        self._firmware_enable_disable(("project_id", "version"), (project_id, version), True)

    def firmware_disable_by_id(self, id: int) -> None:
        self._firmware_enable_disable(("id",), (id,), False)

    def firmware_disable_by_project_version(self, project_id: int, version: str) -> None:
        self._firmware_enable_disable(("project_id", "version"), (project_id, version), False)

    def _firmware_change_target(
        self,
        columns: tuple[str, ...],
        parameters: tuple[int | str, ...],
        target_id: int,
    ) -> None:
        if not columns:
            raise ValueError("At least one column is required")
        if len(columns) != len(parameters):
            raise ValueError("Number of columns must match number of parameters")

        lookup = ", ".join(f"{column}={parameter}" for column, parameter in zip(columns, parameters))
        where_clause = " AND ".join(f"{column} = %s" for column in columns)
        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT id FROM targets WHERE id = %s",
                    (target_id,),
                )
                if cursor.fetchone() is None:
                    raise TargetNotFoundError(f"Target id={target_id} not found")

                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    UPDATE firmware
                    SET
                        target_id = %s,
                        updated_at = %s
                    WHERE {where_clause}
                    """,
                    (target_id, now.isoformat(), *parameters),
                )

                if cursor.rowcount == 1:
                    conn.commit()
                    return

                raise FirmwareNotFoundError(f"Firmware {lookup} not found")
        except MySQLError as e:
            raise DatabaseError(
                f"Database error changing target for firmware {lookup}"
            ) from e

    def firmware_change_target_by_id(self, id: int, target_id: int) -> None:
        self._firmware_change_target(("id",), (id,), target_id)

    def firmware_change_target_by_project_version(self, project_id: int, version: str, target_id: int) -> None:
        self._firmware_change_target(("project_id", "version"), (project_id, version), target_id)

    def _firmware_get(
        self,
        columns: tuple[str, ...],
        parameters: tuple[int | str, ...],
    ) -> Firmware | None:
        if not columns:
            raise ValueError("At least one column is required")
        if len(columns) != len(parameters):
            raise ValueError("Number of columns must match number of parameters")

        where_clause = " AND ".join(f"{column} = %s" for column in columns)

        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT
                        id,
                        project_id,
                        target_id,
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
        except MySQLError as e:
            raise DatabaseError(
                f"Database error retrieving firmware {columns}={parameters}"
            ) from e

    def firmware_get_by_id(self, firmware_id: int) -> Firmware | None:
        return self._firmware_get(("id",), (firmware_id,))

    def firmware_get_by_project_version(
        self,
        project_id: int,
        version: str,
    ) -> Firmware | None:
        return self._firmware_get(("project_id", "version"), (project_id, version))

    def firmware_get_by_project_version_target(
        self,
        project_id: int,
        version: str,
        target_id: int,
    ) -> Firmware | None:
        return self._firmware_get(
            ("project_id", "version", "target_id"),
            (project_id, version, target_id),
        )

    def firmware_is_active(self, firmware_id: int) -> bool:
        try:
            with self._connect() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT is_active FROM firmware WHERE id = %s",
                    (firmware_id,),
                )
                row = cursor.fetchone()
                return bool(row["is_active"]) if row is not None else False
        except MySQLError as e:
            raise DatabaseError(
                f"Database error checking whether firmware {firmware_id} is active"
            ) from e

    def _build_firmware_filters(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> tuple[str, tuple[object, ...]]:
        filters: list[str] = []
        params: list[object] = []
        if is_active is not None:
            filters.append("firmware.is_active = %s")
            params.append(1 if is_active else 0)
        if project_id is not None:
            filters.append("firmware.project_id = %s")
            params.append(project_id)
        where_clause = ""
        if filters:
            where_clause = " WHERE " + " AND ".join(filters)
        return where_clause, tuple(params)

    def firmware_get_record(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[Firmware]:
        try:
            with self._connect() as conn:
                where_clause, params = self._build_firmware_filters(
                    is_active=is_active,
                    project_id=project_id,
                )
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT
                        id,
                        project_id,
                        target_id,
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
                    {where_clause}
                    ORDER BY project_id, id
                    """,
                    params,
                )
                return [self._row_to_firmware(row) for row in cursor.fetchall()]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving firmware") from e

    def firmware_get_list(
        self,
        is_active: bool | None = None,
        project_id: int | None = None,
    ) -> list[FirmwareListItem]:
        try:
            with self._connect() as conn:
                where_clause, params = self._build_firmware_filters(
                    is_active=is_active,
                    project_id=project_id,
                )
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    f"""
                    SELECT
                        firmware.id,
                        projects.name AS project_name,
                        targets.name AS target_name,
                        firmware.version,
                        firmware.filename,
                        firmware.file_size,
                        firmware.channel
                    FROM firmware
                    JOIN projects ON projects.id = firmware.project_id
                    JOIN targets ON targets.id = firmware.target_id
                    {where_clause}
                    ORDER BY projects.name, firmware.version
                    """,
                    params,
                )
                return [self._row_to_firmware_list(row) for row in cursor.fetchall()]
        except MySQLError as e:
            raise DatabaseError("Database error retrieving firmware") from e
