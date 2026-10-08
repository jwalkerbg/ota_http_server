"""Delete operations against a real MySQL server.

Skipped unless OTA_TEST_MYSQL_* variables are set. The database is dedicated to
tests: every table in it is dropped before and after each test.
"""

import os
from pathlib import Path
from types import SimpleNamespace

import mysql.connector
import pytest

from ota_http_server.core.data_models import Device, Firmware, Project, User, UserDevice
from ota_http_server.database import db_mysql_service as m

MIGRATIONS_DIR = (
    Path(__file__).parents[2]
    / "src" / "ota_http_server" / "database" / "migrations" / "mysql"
)

_ENV = {
    "dbhost": os.environ.get("OTA_TEST_MYSQL_HOST"),
    "dbport": int(os.environ.get("OTA_TEST_MYSQL_PORT", "3306")),
    "database": os.environ.get("OTA_TEST_MYSQL_DB"),
    "dbuser": os.environ.get("OTA_TEST_MYSQL_USER"),
    "dbpassword": os.environ.get("OTA_TEST_MYSQL_PASSWORD"),
}

pytestmark = pytest.mark.skipif(
    not all(_ENV[k] for k in ("dbhost", "database", "dbuser", "dbpassword")),
    reason="OTA_TEST_MYSQL_* environment variables are not set",
)


def _drop_all_tables() -> None:
    conn = mysql.connector.connect(
        host=_ENV["dbhost"], port=_ENV["dbport"], database=_ENV["database"],
        user=_ENV["dbuser"], password=_ENV["dbpassword"],
    )
    try:
        cursor = conn.cursor()
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
        cursor.execute("SHOW TABLES")
        for (table,) in cursor.fetchall():
            cursor.execute(f"DROP TABLE `{table}`")
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def db():
    assert _ENV["database"].endswith("_test"), "refusing to wipe a non-test database"
    _drop_all_tables()
    cfg = SimpleNamespace(config={
        "parameters": {"trace_sql": False, "init_db_migrate": True, "migrate_dry_run": False},
        "database": {"mysql": {**_ENV, "dbecho": False, "migrations_dir": str(MIGRATIONS_DIR)}},
    })
    service = m.DatabaseMySQLService(cfg)
    service.init_db()
    yield service
    _drop_all_tables()


def _user(db, username="alice"):
    return db.user_add(User(
        id=None, username=username, password_hash="x", email=f"{username}@example.com",
        role="admin", is_active=True, created_at=None, updated_at=None,
    ))


def _project(db, user, name="smart_air"):
    return db.project_add(Project(
        id=None, name=name, display_name=name, description="d",
        created_by=user.id, is_active=True, created_at=None, updated_at=None,
    ))


def _device(db, project, uuid="uuid-1"):
    target = db.target_get_by_name("Not defined")
    return db.device_add(Device(
        id=None, uuid=uuid, project_id=project.id, target_id=target.id, model="M",
        serial_number=None, current_version="1.0.0", last_seen=None, is_active=True,
        created_at=None, updated_at=None,
    ))


def test_delete_user_by_id_and_username(db):
    first, second = _user(db, "alice"), _user(db, "bob")

    db.user_delete_by_id(first.id)
    db.user_delete_by_username("bob")

    assert db.user_get_by_id(first.id) is None
    assert db.user_get_by_id(second.id) is None


def test_delete_user_not_found(db):
    with pytest.raises(m.UserNotFoundError):
        db.user_delete_by_id(999)
    with pytest.raises(m.UserNotFoundError):
        db.user_delete_by_username("ghost")


def test_delete_user_with_projects_is_rejected(db):
    user = _user(db)
    _project(db, user)

    with pytest.raises(m.UserHasProjectsError):
        db.user_delete_by_id(user.id)

    assert db.user_get_by_id(user.id) is not None


def test_delete_project_by_id_and_name(db):
    user = _user(db)
    first, second = _project(db, user, "p1"), _project(db, user, "p2")

    db.project_delete_by_id(first.id)
    db.project_delete_by_name("p2")

    assert db.project_get_by_id(first.id) is None
    assert db.project_get_by_id(second.id) is None


def test_delete_project_not_found(db):
    with pytest.raises(m.ProjectNotFoundError):
        db.project_delete_by_id(999)
    with pytest.raises(m.ProjectNotFoundError):
        db.project_delete_by_name("ghost")


def test_delete_project_with_device_is_rejected(db):
    project = _project(db, _user(db))
    _device(db, project)

    with pytest.raises(m.ProjectInUseError):
        db.project_delete_by_id(project.id)

    assert db.project_get_by_id(project.id) is not None


def test_delete_project_with_firmware_is_rejected(db):
    project = _project(db, _user(db))
    target = db.target_get_by_name("Not defined")
    db.firmware_add(Firmware(
        id=None, project_id=project.id, target_id=target.id, version="1.0.0",
        filename="fw.bin", file_size=1, checksum="0" * 64, release_notes="n",
        channel="stable", is_active=True, created_at=None, updated_at=None,
    ))

    with pytest.raises(m.ProjectInUseError):
        db.project_delete_by_name(project.name)


def test_delete_device_by_id_and_uuid(db):
    project = _project(db, _user(db))
    first, second = _device(db, project, "u1"), _device(db, project, "u2")

    db.device_delete_by_id(first.id)
    db.device_delete_by_name("u2")

    assert db.device_get_by_id(first.id) is None
    assert db.device_get_by_id(second.id) is None


def test_delete_device_not_found(db):
    with pytest.raises(m.DeviceNotFoundError):
        db.device_delete_by_id(999)
    with pytest.raises(m.DeviceNotFoundError):
        db.device_delete_by_name("ghost")


def test_delete_device_cascades_user_assignments(db):
    user = _user(db)
    device = _device(db, _project(db, user))
    db.user_device_add(UserDevice(
        user_id=user.id, device_id=device.id, created_at=None, expires_at=None,
    ))

    db.device_delete_by_id(device.id)

    assert db.user_device_get(user.id, device.id) is None
