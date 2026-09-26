from types import SimpleNamespace
from tempfile import mkdtemp

from ota_http_server.core.data_models import AppPaths, User
from ota_http_server.core.passwords import Passwords
from ota_http_server.core.server import create_app


def _build_app():
    app_directory = mkdtemp()
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "app_directory": app_directory,
            "www_dir": ".",
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
                "migrations_dir": "src/ota_http_server/database/migrations/sqlite",
            },
        },
    }
    cfg.config["parameters"]["app_paths"] = AppPaths(cfg)
    app = create_app(cfg)
    app.extensions["db_service"].init_db()
    app.extensions["db_service"].user_add(
        User(
            id=None,
            username="api-auth-user",
            password_hash=Passwords.hash("secret"),
            email="api-auth-user@example.com",
            role="admin",
            is_active=True,
            created_at=None,
            updated_at=None,
        )
    )
    return app


def _authenticated_client(app):
    client = app.test_client()
    user = app.extensions["db_service"].user_get_by_username("api-auth-user")
    token = app.extensions["user_auth_service"].create_access_token(user)
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token.token}"
    return client


def test_api_root_returns_version_metadata():
    app = _build_app()

    response = _authenticated_client(app).get("/api/v1/")

    assert response.status_code == 200
    assert response.is_json
    payload = response.get_json()
    assert payload["version"] == "v1"
    assert payload["status"] == "ok"


def test_api_status_returns_expected_shape():
    app = _build_app()

    response = _authenticated_client(app).get("/api/v1/status")

    assert response.status_code == 200
    assert response.is_json
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert "time" in payload


def test_unversioned_status_route_is_not_available():
    app = _build_app()

    response = app.test_client().get("/status")

    assert response.status_code == 404


def test_api_errors_are_returned_as_json():
    app = _build_app()

    response = _authenticated_client(app).get("/api/v1/not-found")

    assert response.status_code == 404
    assert response.is_json
    payload = response.get_json()
    assert payload["error"]["code"] == 404
    assert payload["error"]["message"]


def test_api_exception_handler_returns_json_error():
    app = _build_app()

    @app.route("/api/v1/boom")
    def boom():
        raise RuntimeError("broken")

    response = _authenticated_client(app).get("/api/v1/boom")

    assert response.status_code == 500
    assert response.is_json
    payload = response.get_json()
    assert payload["error"]["code"] == 500
    assert payload["error"]["message"] == "Internal server error"
