# database/migration_mysql_runner.py

import importlib.util
import time
from pathlib import Path
from typing import Any

import mysql.connector

from ota_http_server.core.config import Config
from ota_http_server.database.mysql_sql_tracing import (
    is_sql_tracing_enabled,
    with_mysql_sql_tracing,
)
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)


class MigrationError(Exception):
    pass


class MySQLMigrationConnection:
    def __init__(self, conn: Any):
        self._conn = conn

    def execute(self, sql: str, params: tuple | None = None) -> None:
        cursor = self._conn.cursor()
        try:
            cursor.execute(sql, params or ())
        finally:
            cursor.close()


class MigrationMySQLRunner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        migrations_dir: str = self.cfg.config["database"]["mysql"]["migrations_dir"]
        self.migrations_dir = Path(migrations_dir).expanduser().resolve()

    def _connect(self) -> Any:
        db_config = self.cfg.config["database"]["mysql"]
        conn = mysql.connector.connect(
            host=db_config["dbhost"],
            port=db_config["dbport"],
            database=db_config["database"],
            user=db_config["dbuser"],
            password=db_config["dbpassword"],
        )
        sql_trace_enabled = is_sql_tracing_enabled(
            self.cfg.config["parameters"]["trace_sql"],
            db_config["dbecho"],
        )
        return with_mysql_sql_tracing(conn, logger, sql_trace_enabled)

    def _init_schema_table(self, conn: Any) -> None:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INT PRIMARY KEY,
                    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        finally:
            cursor.close()

    def _get_current_version(self, conn: Any) -> int:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version")
            row = cursor.fetchone()
        finally:
            cursor.close()
        return int(row[0]) if row and row[0] is not None else 0

    def _load_migration(self, path: Path):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise MigrationError(f"Unable to load migration file: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.migration

    def migrate_up(self) -> None:
        logger.verbose("migrate_up start (mysql)")
        conn = self._connect()
        try:
            self._init_schema_table(conn)
            if not self.cfg.config["parameters"]["init_db_migrate"]:
                return

            overall_start = time.perf_counter()
            current_version = self._get_current_version(conn)
            logger.verbose("Current database version = %d", current_version)

            migration_conn = MySQLMigrationConnection(conn)
            for path in sorted(self.migrations_dir.glob("*.py")):
                version = int(path.stem.split("_")[0])
                if version <= current_version:
                    continue

                migration = self._load_migration(path)

                if self.cfg.config["parameters"]["migrate_dry_run"]:
                    logger.info("Pending migration %s: %s", path.name, migration.description)
                    continue

                start = time.perf_counter()
                logger.info("Applying migration %s: %s", path.name, migration.description)
                try:
                    migration.up(migration_conn)
                    migration_conn.execute(
                        "INSERT INTO schema_version(version) VALUES (%s)",
                        (version,),
                    )
                    conn.commit()
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    logger.info("Migration %s completed in %.2f ms", version, elapsed_ms)
                except Exception as error:
                    conn.rollback()
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    raise MigrationError(
                        f"Migration up {version:03d} failed in {elapsed_ms:.2f} ms"
                    ) from error

            overall_ms = (time.perf_counter() - overall_start) * 1000.0
            logger.info("Database is up-to-date. Total migration time: %.2f ms", overall_ms)
        finally:
            conn.close()

    def migrate_down(self) -> None:
        conn = self._connect()
        try:
            self._init_schema_table(conn)
            current_version = self._get_current_version(conn)
            if current_version == 0:
                logger.info("No migrations to rollback")
                return

            migration_file = next(
                self.migrations_dir.glob(f"{current_version:03d}_*.py"),
                None,
            )
            if migration_file is None:
                raise MigrationError(
                    f"Migration file for version {current_version:03d} not found"
                )

            migration = self._load_migration(migration_file)

            if self.cfg.config["parameters"]["migrate_dry_run"]:
                logger.info(
                    "Pending migration to rollback %s: %s",
                    migration_file.name,
                    migration.description,
                )
                return

            start = time.perf_counter()
            migration_conn = MySQLMigrationConnection(conn)
            try:
                logger.info("Rolling back %s", migration_file.name)
                migration.down(migration_conn)
                migration_conn.execute(
                    "DELETE FROM schema_version WHERE version = %s",
                    (current_version,),
                )
                conn.commit()
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                logger.info("Rollback %s completed in %.2f ms", current_version, elapsed_ms)
            except Exception as error:
                conn.rollback()
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                raise MigrationError(
                    f"Migration down {current_version:03d} failed in {elapsed_ms:.2f} ms"
                ) from error
        finally:
            conn.close()
