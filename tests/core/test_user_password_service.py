"""Tests for UserService password management and the CLI password-change command."""

import getpass
from pathlib import Path
from types import SimpleNamespace

import pytest

from ota_http_server.core.data_models import AppPaths, User
from ota_http_server.core.password_policy import PasswordPolicyError
from ota_http_server.core.passwords import Passwords
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.user.user_service import (
    CurrentPasswordMismatchError,
    InactiveUserError,
    UserNotFoundError,
    UserService,
)

MIGRATIONS_DIR = (
    Path(__file__).parents[2]
    / "src"
    / "ota_http_server"
    / "database"
    / "migrations"
    / "sqlite"
)


@pytest.fixture()
def cfg(tmp_path):
    cfg = SimpleNamespace()
    cfg.config = {
        "parameters": {
            "app_directory": str(tmp_path),
            "www_dir": "www",
            "firmware_dir": "firmware",
            "url_firmware": "firmware",
            "trace_sql": False,
            "init_db_migrate": True,
            "migrate_dry_run": False,
            "user_id": None,
            "username": None,
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
    return cfg


@pytest.fixture()
def db(cfg):
    db_service = DatabaseService(cfg)
    db_service.init_db()
    cfg.config["db_service"] = db_service
    return db_service


@pytest.fixture()
def service(cfg, db):
    return UserService(cfg)


@pytest.fixture()
def make_user(db):
    def _make(username="alice", password="old-secret", role="admin", is_active=True):
        return db.user_add(
            User(
                id=None,
                username=username,
                password_hash=Passwords.hash(password),
                email=f"{username}@example.com",
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


# ---------------------------------------------------------------------------
# change_password (self-service)
# ---------------------------------------------------------------------------


def test_change_password_success(service, db, user):
    service.change_password(user.id, "old-secret", "new-secret", "new-secret")

    stored = db.user_get_by_id(user.id)
    assert Passwords.verify("new-secret", stored.password_hash)


def test_change_password_rejects_incorrect_current_password(service, db, user):
    with pytest.raises(CurrentPasswordMismatchError):
        service.change_password(user.id, "wrong-secret", "new-secret", "new-secret")

    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_change_password_nonexistent_user(service):
    with pytest.raises(UserNotFoundError):
        service.change_password(999, "old-secret", "new-secret", "new-secret")


def test_change_password_inactive_user(service, db, make_user):
    inactive = make_user(username="inactive", is_active=False)

    with pytest.raises(InactiveUserError):
        service.change_password(inactive.id, "old-secret", "new-secret", "new-secret")

    assert Passwords.verify("old-secret", db.user_get_by_id(inactive.id).password_hash)


def test_change_password_stores_only_hash(service, db, user):
    service.change_password(user.id, "old-secret", "new-secret", "new-secret")

    stored = db.user_get_by_id(user.id)
    assert stored.password_hash != "new-secret"
    assert "new-secret" not in stored.password_hash
    assert stored.password_hash.startswith("$argon2")


def test_change_password_old_password_no_longer_works(service, db, user):
    service.change_password(user.id, "old-secret", "new-secret", "new-secret")

    assert not Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_change_password_new_password_works(service, db, user):
    service.change_password(user.id, "old-secret", "new-secret", "new-secret")

    assert Passwords.verify("new-secret", db.user_get_by_id(user.id).password_hash)


def test_change_password_confirmation_mismatch(service, db, user):
    with pytest.raises(PasswordPolicyError, match="does not match"):
        service.change_password(user.id, "old-secret", "new-secret", "other-secret")

    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_change_password_policy_failure(service, db, user):
    with pytest.raises(PasswordPolicyError, match="at least"):
        service.change_password(user.id, "old-secret", "short", "short")

    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_change_password_rejects_empty_new_password(service, user):
    with pytest.raises(PasswordPolicyError, match="must not be empty"):
        service.change_password(user.id, "old-secret", "", "")


def test_change_password_does_not_modify_status_or_role(service, db, make_user):
    operator = make_user(username="operator", role="operator")

    service.change_password(operator.id, "old-secret", "new-secret", "new-secret")

    stored = db.user_get_by_id(operator.id)
    assert stored.role == "operator"
    assert stored.is_active is True
    assert stored.username == "operator"
    assert stored.email == "operator@example.com"


def test_change_password_uses_configured_policy(service, db, user):
    service.cfg.config["parameters"]["password_min_length"] = 16

    with pytest.raises(PasswordPolicyError, match="at least 16"):
        service.change_password(user.id, "old-secret", "new-secret", "new-secret")

    service.change_password(user.id, "old-secret", "a" * 16, "a" * 16)
    assert Passwords.verify("a" * 16, db.user_get_by_id(user.id).password_hash)


# ---------------------------------------------------------------------------
# reset_password (administrative)
# ---------------------------------------------------------------------------


def test_reset_password_success_without_current_password(service, db, user):
    service.reset_password(user.id, "new-secret", "new-secret")

    stored = db.user_get_by_id(user.id)
    assert Passwords.verify("new-secret", stored.password_hash)
    assert not Passwords.verify("old-secret", stored.password_hash)


def test_reset_password_nonexistent_user(service):
    with pytest.raises(UserNotFoundError):
        service.reset_password(999, "new-secret", "new-secret")


def test_reset_password_allows_inactive_user_without_activating(service, db, make_user):
    inactive = make_user(username="inactive", is_active=False)

    service.reset_password(inactive.id, "new-secret", "new-secret")

    stored = db.user_get_by_id(inactive.id)
    assert Passwords.verify("new-secret", stored.password_hash)
    assert stored.is_active is False


def test_reset_password_confirmation_mismatch(service, db, user):
    with pytest.raises(PasswordPolicyError, match="does not match"):
        service.reset_password(user.id, "new-secret", "other-secret")

    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_reset_password_policy_failure(service, db, user):
    with pytest.raises(PasswordPolicyError, match="at least"):
        service.reset_password(user.id, "short", "short")


# ---------------------------------------------------------------------------
# CLI password-change command
# ---------------------------------------------------------------------------


def test_parse_args_user_password_change_command(monkeypatch):
    import sys

    from ota_http_server.core.config import parse_args

    monkeypatch.setattr(
        sys,
        "argv",
        ["ota_http_server", "user", "password-change", "--username", "john"],
    )

    parsed = parse_args()

    assert parsed.command == "user"
    assert parsed.user_command == "password-change"
    assert parsed.username == "john"
    # passwords are never command-line arguments
    assert not hasattr(parsed, "new_password")
    assert not hasattr(parsed, "user_password") or parsed.user_password is None


def _cli_cfg(cfg, db, *, user_id=None, username=None):
    cfg.config["user_command"] = "password-change"
    cfg.config["parameters"]["user_id"] = user_id
    cfg.config["parameters"]["username"] = username
    cfg.config["db_service"] = db
    return cfg


def _patch_getpass(monkeypatch, new_password, confirm_password):
    prompts = iter([new_password, confirm_password])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(prompts))


def test_cli_password_change_success(service, db, user, monkeypatch):
    _cli_cfg(service.cfg, db, username=user.username)
    _patch_getpass(monkeypatch, "new-secret", "new-secret")

    service.command_handler()

    stored = db.user_get_by_id(user.id)
    assert Passwords.verify("new-secret", stored.password_hash)
    assert not Passwords.verify("old-secret", stored.password_hash)


def test_cli_password_change_by_user_id(service, db, user, monkeypatch):
    _cli_cfg(service.cfg, db, user_id=user.id)
    _patch_getpass(monkeypatch, "new-secret", "new-secret")

    service.command_handler()

    assert Passwords.verify("new-secret", db.user_get_by_id(user.id).password_hash)


def test_cli_password_change_nonexistent_user(service, db, monkeypatch):
    _cli_cfg(service.cfg, db, username="ghost")
    _patch_getpass(monkeypatch, "new-secret", "new-secret")

    with pytest.raises(UserNotFoundError):
        service.command_handler()


def test_cli_password_change_requires_user_selection(service, db):
    _cli_cfg(service.cfg, db)

    with pytest.raises(ValueError, match="User id or username must be provided"):
        service.command_handler()


def test_cli_password_change_confirmation_mismatch(service, db, user, monkeypatch):
    _cli_cfg(service.cfg, db, username=user.username)
    _patch_getpass(monkeypatch, "new-secret", "other-secret")

    with pytest.raises(PasswordPolicyError, match="does not match"):
        service.command_handler()

    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_cli_password_change_invalid_password(service, db, user, monkeypatch):
    _cli_cfg(service.cfg, db, username=user.username)
    _patch_getpass(monkeypatch, "short", "short")

    with pytest.raises(PasswordPolicyError):
        service.command_handler()

    assert Passwords.verify("old-secret", db.user_get_by_id(user.id).password_hash)


def test_cli_password_change_never_prints_passwords(service, db, user, monkeypatch, caplog):
    _cli_cfg(service.cfg, db, username=user.username)
    _patch_getpass(monkeypatch, "new-secret", "new-secret")

    service.command_handler()

    assert "new-secret" not in caplog.text
    assert "old-secret" not in caplog.text


def test_cli_password_change_uses_existing_hashing(service, db, user, monkeypatch):
    _cli_cfg(service.cfg, db, username=user.username)
    _patch_getpass(monkeypatch, "new-secret", "new-secret")

    service.command_handler()

    stored = db.user_get_by_id(user.id)
    assert stored.password_hash != "new-secret"
    assert stored.password_hash.startswith("$argon2")
    assert Passwords.verify("new-secret", stored.password_hash)


def test_cli_password_change_logs_admin_activity(service, db, user, monkeypatch):
    activity_logger = SimpleNamespace(calls=[])

    def _log_activity(**kwargs):
        activity_logger.calls.append(kwargs)

    activity_logger.log_activity = _log_activity
    service.admin_activity_logger = activity_logger

    _cli_cfg(service.cfg, db, username=user.username)
    _patch_getpass(monkeypatch, "new-secret", "new-secret")

    service.command_handler()

    assert len(activity_logger.calls) == 1
    event = activity_logger.calls[0]
    assert event["action"] == "password-change"
    assert event["outcome"] == "success"
    assert event["entity"] == "user"
    assert event["target"]["user_id"] == user.id
    assert event["target"]["username"] == user.username
    assert "new-secret" not in str(event)
