from types import SimpleNamespace

from ota_http_server.core.server import create_app


def _build_app():
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "www_dir": ".",
            "firmware_dir": "firmware",
            "url_firmware": "firmware",
            "no_jwt": True,
            "jwt_alg": "HS256",
            "jwt_expiry": 60,
            "jwt_max_expiry": 120,
            "jwt_secret": "secret",
            "jwt_issuer": "issuer",
            "jwt_audience": "audience",
            "admin_secret": "admin-secret",
            "app_paths": SimpleNamespace(project_dir=lambda project_name: SimpleNamespace(), logs_dir="."),
        },
        "database": {
            "dbtype": "sqlite",
            "sqlite": {
                "db_file": ":memory:",
                "migrations_dir": "src/ota_http_server/database/migrations/sqlite",
            },
        },
    }
    return create_app(cfg)


def test_api_root_returns_version_metadata():
    app = _build_app()

    response = app.test_client().get("/api/v1/")

    assert response.status_code == 200
    assert response.is_json
    payload = response.get_json()
    assert payload["version"] == "v1"
    assert payload["status"] == "ok"


def test_api_status_matches_legacy_status_shape():
    app = _build_app()

    response = app.test_client().get("/api/v1/status")

    assert response.status_code == 200
    assert response.is_json
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert "time" in payload


def test_api_errors_are_returned_as_json():
    app = _build_app()

    response = app.test_client().get("/api/v1/not-found")

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

    response = app.test_client().get("/api/v1/boom")

    assert response.status_code == 500
    assert response.is_json
    payload = response.get_json()
    assert payload["error"]["code"] == 500
    assert payload["error"]["message"] == "Internal server error"
