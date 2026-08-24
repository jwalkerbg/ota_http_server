# database/migration_sqlite3_runner.py

import time
import sqlite3
import importlib.util
from pathlib import Path

from ota_http_server.core.config import Config
from ota_http_server.core.data_models import AppPaths
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class MigrationError(Exception):
    pass

class MigrationRunner:
    def __init__(self, cfg:Config):
        self.cfg = cfg
        migrations_dir: str = self.cfg.config["database"]["sqlite"]["migrations_dir"]
        self.migrations_dir = Path(migrations_dir).expanduser().resolve()
        self.app_paths:AppPaths = self.cfg.config['parameters']['app_paths']

    def _connect(self):
        conn = sqlite3.connect(self.app_paths.database_sqlite)
        conn.execute("PRAGMA foreign_keys = ON;")
        if  self.cfg.config["parameters"]["trace_sql"]:
            conn.set_trace_callback(lambda sql: logger.debug("SQL: %s", sql))
        return conn

    def _init_schema_table(self, conn):
        conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)

    def _get_current_version(self, conn) -> int:
        row = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        return row[0] or 0

    def _load_migration(self, path: Path):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.migration

    def migrate_up(self):
        logger.verbose("migrate_up start")
        with self._connect() as conn:
            self._init_schema_table(conn)
            if not self.cfg.config["parameters"]["init_db_migrate"]:
                return

            overall_start = time.perf_counter()
            current_version = self._get_current_version(conn)
            logger.verbose(f"Current database version = %d",current_version)
            for path in sorted(self.migrations_dir.glob("*.py")):
                version = int(path.stem.split("_")[0])

                if version <= current_version:
                    continue

                migration = self._load_migration(path)

                if not self.cfg.config["parameters"]["migrate_dry_run"]:
                    start = time.perf_counter()
                    logger.info("Applying migration %s: %s", path.name, migration.description)
                    try:
                        # Start transaction
                        conn.execute("BEGIN")
                        migration.up(conn)
                        conn.execute("INSERT INTO schema_version(version) VALUES (?)",(version,))
                        conn.commit()
                        elapsed_ms = (time.perf_counter() - start) * 1000.0
                        logger.info("Migration %s completed in %.2f ms", version, elapsed_ms)
                    except Exception as e:
                        conn.rollback()
                        elapsed_ms = (time.perf_counter() - start) * 1000.0
                        raise MigrationError("Migration up {version:03d} failed in {elapsed_ms.2f} ms") from e
                else:
                    logger.info("Pending migration %s: %s", path.name, migration.description)

            overall_ms = (time.perf_counter() - overall_start) * 1000.0
            logger.info("Database is up-to-date. Total migration time: %.2f ms", overall_ms)

    def migrate_down(self):
        with self._connect() as conn:
            self._init_schema_table(conn)
            current_version = self._get_current_version(conn)
            if current_version == 0:
                logger.info("No migrations to rollback")
                return

            if  self.cfg.config["parameters"]["trace_sql"]:
                conn.set_trace_callback(
                    lambda sql: logger.debug("SQL: %s", sql)
                )
            migration_file = next(self.migrations_dir.glob(f"{current_version:03d}_*.py"))

            migration = self._load_migration(migration_file)

            if not self.cfg.config["parameters"]["migrate_dry_run"]:
                start = time.perf_counter()
                try:
                    # Start transaction
                    conn.execute("BEGIN")
                    print(f"Rolling back {migration_file.name}")
                    migration.down(conn)
                    conn.execute("DELETE FROM schema_version WHERE version = ?",(current_version,))
                    conn.commit()
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    logger.info("Rollback %s completed in %.2f ms", current_version, elapsed_ms)
                except Exception as e:
                    conn.rollback()
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    raise MigrationError("Migration down {version:03d} failed in {elapsed_ms:.2f} ms") from e
            else:
                logger.info("Pending migration to rollback %s: %s", migration_file.name, migration.description)
