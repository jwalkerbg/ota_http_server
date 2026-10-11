"""Operations against a real PostgreSQL server.

Skipped unless OTA_TEST_PG_* variables are set. Every test runs in its own
throw-away schema (selected through PGOPTIONS), so existing data is untouched.
"""

import inspect
import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest

from ota_http_server.core.data_models import Device, Firmware, Project, Target, User, UserDevice
from ota_http_server.database import db_postgres_service as m
from ota_http_server.database.database_interface import DatabaseInterface

MIGRATIONS_DIR = (
    Path(__file__).parents[2]
    / "src" / "ota_http_server" / "database" / "migrations" / "postgresql"
)

_ENV = {
    "pghost": os.environ.get("OTA_TEST_PG_HOST"),
    "pgport": int(os.environ.get("OTA_TEST_PG_PORT", "5432")),
    "pgdatabase": os.environ.get("OTA_TEST_PG_DB"),
    "pguser": os.environ.get("OTA_TEST_PG_USER"),
    "pgpassword": os.environ.get("OTA_TEST_PG_PASSWORD"),
}

pytestmark = pytest.mark.skipif(
    not all(_ENV[k] for k in ("pghost", "pgdatabase", "pguser", "pgpassword")),
    reason="OTA_TEST_PG_* environment variables are not set",
)


def _admin_execute(sql: str) -> None:
    with psycopg.connect(
        host=_ENV["pghost"], port=_ENV["pgport"], dbname=_ENV["pgdatabase"],
        user=_ENV["pguser"], password=_ENV["pgpassword"], autocommit=True,
    ) as conn:
        conn.execute(sql)


def _make_cfg() -> SimpleNamespace:
    return SimpleNamespace(config={
        "parameters": {"trace_sql": False, "init_db_migrate": True, "migrate_dry_run": False},
        "database": {"postgresql": {
            **_ENV, "pgecho": False, "pgpool_size": 1, "migrations_dir": str(MIGRATIONS_DIR),
        }},
    })


@pytest.fixture()
def db(monkeypatch):
    schema = f"ota_test_{uuidlib.uuid4().hex[:12]}"
    _admin_execute(f"CREATE SCHEMA {schema}")
    monkeypatch.setenv("PGOPTIONS", f"-c search_path={schema}")
    service = m.DatabasePostgreSQLService(_make_cfg())
    service.init_db()
    yield service
    _admin_execute(f"DROP SCHEMA {schema} CASCADE")


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


def _device(db, project, uuid="uuid-1", serial=None):
    target = db.target_get_by_name("Not defined")
    return db.device_add(Device(
        id=None, uuid=uuid, project_id=project.id, target_id=target.id, model="M",
        serial_number=serial, current_version="1.0.0", last_seen=None, is_active=True,
        created_at=None, updated_at=None,
    ))


def _firmware(db, project, version="1.0.0", target=None):
    target = target or db.target_get_by_name("Not defined")
    return db.firmware_add(Firmware(
        id=None, project_id=project.id, target_id=target.id, version=version,
        filename=f"fw-{version}.bin", file_size=1, checksum="0" * 64, release_notes="n",
        channel="stable", is_active=False, created_at=None, updated_at=None,
    ))


def test_implements_database_interface():
    for name, _ in inspect.getmembers(DatabaseInterface, inspect.isfunction):
        if not name.startswith("_"):
            assert hasattr(m.DatabasePostgreSQLService, name), name


def test_migrate_is_idempotent_and_rolls_back(db):
    db.migrate()
    for _ in range(8):
        db.rollback()
    with psycopg.connect(
        host=_ENV["pghost"], port=_ENV["pgport"], dbname=_ENV["pgdatabase"],
        user=_ENV["pguser"], password=_ENV["pgpassword"],
    ) as conn:
        conn.execute("SELECT version FROM schema_version LIMIT 0")
    db.rollback()  # nothing left to roll back
    db.migrate()
    assert db.target_get_by_name("Not defined") is not None


def test_user_lifecycle(db):
    user = _user(db)
    assert user.id and user.created_at is not None
    assert db.user_get_by_username("alice").email == "alice@example.com"
    assert db.user_is_active(user.id)

    db.user_disable_by_id(user.id)
    assert not db.user_is_active(user.id)
    with pytest.raises(m.UserAlreadyDisabledError):
        db.user_disable_by_username("alice")
    db.user_enable_by_username("alice")
    with pytest.raises(m.UserAlreadyEnabledError):
        db.user_enable_by_id(user.id)
    with pytest.raises(m.UserNotFoundError):
        db.user_enable_by_id(999)

    _user(db, "bob")
    db.user_disable_by_username("bob")
    assert [u.username for u in db.user_get_list(is_active=True)] == ["alice"]
    assert [u.username for u in db.user_get_list(is_active=False)] == ["bob"]
    assert [u.username for u in db.user_get_list()] == ["alice", "bob"]

    updated = db.user_update_by_id(user.id, role="user", email="a@x.org")
    assert (updated.role, updated.email, updated.updated_at is not None) == ("user", "a@x.org", True)
    db.user_set_password_by_id(user.id, "newhash")
    assert db.user_get_by_id(user.id).password_hash == "newhash"
    with pytest.raises(m.UserNotFoundError):
        db.user_update_by_id(999, role="user")
    with pytest.raises(m.UserNotFoundError):
        db.user_set_password_by_id(999, "h")


def test_user_duplicates(db):
    _user(db)
    with pytest.raises(m.UserAlreadyExistsError):
        _user(db)
    other = _user(db, "bob")
    with pytest.raises(m.UserAlreadyExistsError):
        db.user_update_by_id(other.id, username="alice")
    with pytest.raises(m.UserAlreadyExistsError):
        db.user_update_by_id(other.id, email="alice@example.com")


def test_delete_user_with_projects_is_rejected(db):
    user = _user(db)
    _project(db, user)
    with pytest.raises(m.UserHasProjectsError):
        db.user_delete_by_id(user.id)
    with pytest.raises(m.UserNotFoundError):
        db.user_delete_by_username("ghost")


def test_project_lifecycle(db):
    user = _user(db)
    project = _project(db, user)
    assert db.project_get_by_name("smart_air").id == project.id
    with pytest.raises(m.ProjectAlreadyExistsError):
        _project(db, user)

    db.project_disable_by_name("smart_air")
    assert not db.project_is_active(project.id)
    with pytest.raises(m.ProjectAlreadyDisabledError):
        db.project_disable_by_id(project.id)
    db.project_enable_by_id(project.id)
    with pytest.raises(m.ProjectAlreadyEnabledError):
        db.project_enable_by_name("smart_air")

    updated = db.project_update_by_id(project.id, display_name="Smart Air")
    assert updated.display_name == "Smart Air"
    assert [p.name for p in db.project_get_list(is_active=True)] == ["smart_air"]
    assert db.project_get_list(is_active=False) == []
    assert db.project_get_list()[0].created_by_username == "alice"

    db.project_delete_by_name("smart_air")
    with pytest.raises(m.ProjectNotFoundError):
        db.project_delete_by_id(project.id)


def test_target_add_and_duplicates(db):
    target = db.target_add(Target(id=None, name="esp32"))
    assert db.target_get_by_id(target.id).name == "esp32"
    with pytest.raises(m.TargetAlreadyExistsError):
        db.target_add(Target(id=None, name="esp32"))
    assert [t.name for t in db.target_get_list()] == ["Not defined", "esp32"]


def test_device_lifecycle(db):
    user = _user(db)
    project = _project(db, user)
    device = _device(db, project, "u1", serial="S1")

    with pytest.raises(m.DeviceAlreadyExistsError):
        _device(db, project, "u1")
    with pytest.raises(m.DeviceAlreadyExistsError):
        _device(db, project, "u2", serial="S1")

    db.device_disable_by_name("u1")
    assert not db.device_is_active(device.id)
    with pytest.raises(m.DeviceAlreadyDisabledError):
        db.device_disable_by_id(device.id)
    db.device_enable_by_id(device.id)
    with pytest.raises(m.DeviceAlreadyEnabledError):
        db.device_enable_by_name("u1")

    target = db.target_add(Target(id=None, name="esp32"))
    db.device_change_target_by_id(device.id, target.id)
    assert db.device_get_by_name("u1").target_id == target.id
    assert len(db.device_get_list(is_active=True)) == 1
    assert db.device_get_record(is_active=False) == []

    updated = db.device_update_by_id(device.id, model="M2")
    assert updated.model == "M2"
    db.device_delete_by_name("u1")
    with pytest.raises(m.DeviceNotFoundError):
        db.device_delete_by_id(device.id)


def test_user_device_assignments(db):
    user = _user(db)
    device = _device(db, _project(db, user))
    db.user_device_add(UserDevice(user_id=user.id, device_id=device.id, created_at=None, expires_at=None))
    with pytest.raises(m.UserDeviceAlreadyExistsError):
        db.user_device_add(UserDevice(user_id=user.id, device_id=device.id, created_at=None, expires_at=None))

    assert not db.user_device_is_expired(user.id, device.id)
    past = datetime.now(UTC) - timedelta(days=1)
    assert db.user_device_set_expiry(user.id, device.id, past).expires_at == past
    assert db.user_device_is_expired(user.id, device.id)

    db.device_delete_by_id(device.id)
    assert db.user_device_get(user.id, device.id) is None
    with pytest.raises(m.UserDeviceNotFoundError):
        db.user_device_delete(user.id, device.id)


def test_firmware_lifecycle(db):
    project = _project(db, _user(db))
    firmware = _firmware(db, project)
    assert firmware.id
    with pytest.raises(m.FirmwareAlreadyExistsError):
        _firmware(db, project)

    db.firmware_enable_by_project_version(project.id, "1.0.0")
    assert db.firmware_is_active(firmware.id)
    with pytest.raises(m.FirmwareAlreadyEnabledError):
        db.firmware_enable_by_id(firmware.id)
    db.firmware_disable_by_id(firmware.id)
    with pytest.raises(m.FirmwareAlreadyDisabledError):
        db.firmware_disable_by_project_version(project.id, "1.0.0")

    target = db.target_add(Target(id=None, name="esp32"))
    db.firmware_change_target_by_id(firmware.id, target.id)
    assert db.firmware_get_by_project_version_target(project.id, "1.0.0", target.id).id == firmware.id
    assert db.firmware_get_by_project_version(project.id, "1.0.0").id == firmware.id
    assert len(db.firmware_get_list()) == 1

    replaced = db.firmware_replace(firmware.id, "new.bin", 42, "f" * 64)
    assert (replaced.filename, replaced.file_size) == ("new.bin", 42)

    with pytest.raises(m.ProjectInUseError):
        db.project_delete_by_id(project.id)

    info = db.firmware_delete_by_id(firmware.id)
    assert (info.project_name, info.filename) == ("smart_air", "new.bin")
    with pytest.raises(m.FirmwareNotFoundError):
        db.firmware_delete_by_id(firmware.id)

    _firmware(db, project, "2.0.0")
    assert db.firmware_delete_by_project_version(project.id, "2.0.0").filename == "fw-2.0.0.bin"
    with pytest.raises(m.FirmwareNotFoundError):
        db.firmware_delete_by_project_version(project.id, "2.0.0")
