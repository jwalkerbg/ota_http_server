import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from ota_http_server.core.data_models import AppPaths, Device, Firmware, Project, User
from ota_http_server.core.passwords import Passwords
from ota_http_server.core.server import create_app

MIGRATIONS_DIR = (
    Path(__file__).parents[2]
    / "src"
    / "ota_http_server"
    / "database"
    / "migrations"
    / "sqlite"
)


@pytest.fixture()
def app(tmp_path):
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "app_directory": str(tmp_path),
            "www_dir": "www",
            "firmware_dir": "firmware",
            "url_firmware": "firmware",
            "jwt_alg": "HS256",
            "jwt_expiry": 60,
            "jwt_max_expiry": 120,
            "jwt_secret": "secret",
            "jwt_issuer": "issuer",
            "jwt_audience": "audience",
            "admin_secret": "admin-secret",
            "trace_sql": False,
            "init_db_migrate": True,
            "migrate_dry_run": False,
        },
        "database": {
            "dbtype": "sqlite",
            "sqlite": {
                "db_file": "test.db",
                "migrations_dir": str(MIGRATIONS_DIR),
            },
        },
    }
    cfg.config["parameters"]["app_paths"] = AppPaths(cfg)

    application = create_app(cfg)
    application.extensions["db_service"].init_db()
    application.extensions["api_authenticated_user_loader"] = lambda: SimpleNamespace(role="admin")
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def authenticated_client(app, client, make_user):
    auth_user = make_user(username="api-auth-user")
    token = app.extensions["user_auth_service"].create_access_token(auth_user)
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token.token}"
    return client


@pytest.fixture()
def set_api_role(app):
    def _set_api_role(role: str) -> None:
        app.extensions["api_authenticated_user_loader"] = lambda: SimpleNamespace(role=role)

    return _set_api_role


@pytest.fixture()
def db(app):
    return app.extensions["db_service"]


@pytest.fixture()
def make_user(db):
    def _make(username="alice", email=None, role="admin", is_active=True):
        return db.user_add(
            User(
                id=None,
                username=username,
                password_hash=Passwords.hash("secret"),
                email=email or f"{username}@example.com",
                role=role,
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


@pytest.fixture()
def user(make_user):
    return make_user()


@pytest.fixture()
def make_project(db):
    def _make(name="smart_air", created_by=None, is_active=True, display_name=None):
        return db.project_add(
            Project(
                id=None,
                name=name,
                display_name=display_name or name.replace("_", " ").title(),
                description=f"{name} description",
                created_by=created_by,
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


@pytest.fixture()
def project(make_project, user):
    return make_project(created_by=user.id)


@pytest.fixture()
def make_device(db):
    def _make(
        uuid="uuid-1",
        project_id=None,
        serial_number=None,
        is_active=True,
        target_id=None,
        current_version="1.0.0",
    ):
        if target_id is None:
            target = db.target_get_by_name("Not defined")
            target_id = target.id
        return db.device_add(
            Device(
                id=None,
                uuid=uuid,
                project_id=project_id,
                target_id=target_id,
                model="ESP32S3",
                serial_number=serial_number,
                current_version=current_version,
                last_seen=None,
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


@pytest.fixture()
def device(make_device, project):
    return make_device(project_id=project.id, serial_number="SN-1")


@pytest.fixture()
def make_firmware(db, app):
    def _make(project, version="1.0.0", content=b"firmware-image", is_active=True):
        app_paths = app.extensions["app_paths"]
        target = db.target_get_by_name("Not defined")
        project_dir = app_paths.ensure_project_dir(project.name)
        image = project_dir / f"fw-{version}.bin"
        image.write_bytes(content)
        return db.firmware_add(
            Firmware(
                id=None,
                project_id=project.id,
                target_id=target.id,
                version=version,
                filename=image.name,
                file_size=len(content),
                checksum=hashlib.sha256(content).hexdigest(),
                release_notes="notes",
                channel="stable",
                is_active=is_active,
                created_at=None,
                updated_at=None,
            )
        )

    return _make


@pytest.fixture()
def firmware(make_firmware, project):
    return make_firmware(project)
