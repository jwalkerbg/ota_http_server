from ota_http_server.core import app_runner
from ota_http_server.core.config import Config


def test_db_cli_logs_database_error_without_masking_it(tmp_path, monkeypatch, caplog):
    cfg = Config()
    cfg.config["command"] = "db"
    cfg.config["parameters"]["app_directory"] = str(tmp_path)
    cfg.config["logging"]["exc_full_stack"] = False

    class FailingDatabaseService:
        def __init__(self, _cfg):
            pass

        def db_command_handler(self):
            raise RuntimeError("Migration 005 failed")

    monkeypatch.setattr(app_runner, "DatabaseService", FailingDatabaseService)
    monkeypatch.setattr(app_runner, "build_admin_activity_logger", lambda _cfg: None)
    monkeypatch.setattr(app_runner, "build_ota_download_logger", lambda _cfg: None)

    app_runner.run_app(cfg)

    assert "Migration 005 failed" in caplog.text
    assert "UnboundLocalError" not in caplog.text