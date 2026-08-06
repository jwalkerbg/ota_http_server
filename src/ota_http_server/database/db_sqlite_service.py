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

    def user_enable_by_id(self, user_id: int) -> None:
        """
        Enable a user account.

        Only the active state is changed.

        Args:
            user_id: Database id of the user.

        Returns:
            Updated User object.

        Raises:
            UserNotFoundError:
                If the user does not exist.
            UserAlreadyEnabledError:
                If the user is already enabled.
            DatabaseError:
                For unexpected database errors.
        """

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    SELECT
                        id,
                        is_active
                    FROM users
                    WHERE id = ?
                    """,
                    (user_id,)
                )

                row = cursor.fetchone()

                if row is None:
                    raise UserNotFoundError(
                        f"User id={user_id} does not exist"
                    )

                if row["is_active"] == 1:
                    raise UserAlreadyEnabledError(
                        f"User id={user_id} is already enabled"
                    )

                conn.execute(
                    """
                    UPDATE users
                    SET
                        is_active = 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (now.isoformat(), user_id)
                )
                conn.commit()

        except (UserNotFoundError, UserAlreadyEnabledError):
            raise

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error enabling user id={user_id}"
            ) from e

    def user_enable_by_username(self, username: str) -> None:

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    UPDATE users
                    SET
                        is_active = 1,
                        updated_at = ?
                    WHERE username = ?
                    AND is_active = 0
                    """,
                    (
                        now.isoformat(),
                        username,
                    )
                )

                if cursor.rowcount == 0:
                    raise UserNotFoundError(
                        f"User '{username}' does not exist "
                        "or is already enabled"
                    )

                conn.commit()

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error enabling user '{username}'"
            ) from e

    def user_disable_by_id(self, user_id: int) -> None:
        """
        Disable a user account.

        The user record is kept for audit purposes.
        Only the active state is changed.

        Args:
            user_id: Database id of the user.

        Returns:
            Updated User object.

        Raises:
            UserNotFoundError:
                If the user does not exist.
            UserAlreadyDisabledError:
                If the user is already disabled.
            DatabaseError:
                For unexpected database errors.
        """

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    SELECT
                        id,
                        is_active
                    FROM users
                    WHERE id = ?
                    """,
                    (user_id,)
                )

                row = cursor.fetchone()

                if row is None:
                    raise UserNotFoundError(
                        f"User id={user_id} does not exist"
                    )

                if row["is_active"] == 0:
                    raise UserAlreadyDisabledError(
                        f"User id={user_id} is already disabled"
                    )

                conn.execute(
                    """
                    UPDATE users
                    SET
                        is_active = 0,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (now.isoformat(), user_id)
                )
                conn.commit()

        except (UserNotFoundError, UserAlreadyDisabledError):
            raise

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error disabling user id={user_id}"
            ) from e

    def user_disable_by_username(self, username: str) -> None:

        now = datetime.now(UTC)

        try:
            with self._connect() as conn:

                cursor = conn.execute(
                    """
                    UPDATE users
                    SET
                        is_active = 0,
                        updated_at = ?
                    WHERE username = ?
                    AND is_active = 1
                    """,
                    (
                        now.isoformat(),
                        username,
                    )
                )

                if cursor.rowcount == 0:
                    raise UserNotFoundError(
                        f"User '{username}' does not exist "
                        "or is already disabled"
                    )

                conn.commit()

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error disabling user '{username}'"
            ) from e

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

    def user_get_by_id(self, user_id: int) -> User | None:

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
                    WHERE id = ?
                    """,
                    (user_id,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_user(row)

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error retrieving user id={user_id}"
            ) from e

    def user_get_by_username(self, username: str) -> User | None:

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
                    WHERE username = ?
                    """,
                    (username,)
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_user(row)

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error retrieving user '{username}'"
            ) from e

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
                        f"Database Integrity violation: User id={project.created_by} does not exist"
                    ) from e

                case _:
                    raise DatabaseError(
                        f"Database integrity error creating project '{project.name}': {str(e)}"
                    ) from e
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Database error creating project '{project.name}'"
            ) from e
