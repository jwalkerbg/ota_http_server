# user_service.py

import getpass

from ota_http_server.core.config import Config
from ota_http_server.core.passwords import Passwords
from ota_http_server.core.password_policy import PasswordPolicy
from ota_http_server.core.data_models import User
from ota_http_server.core.formatters import UserFormatter
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger
from ota_http_server.logger.admin_activity_logger import normalize_admin_activity_action

logger = get_app_logger(__name__)


class UserServiceError(Exception):
    """Base class for user service failures."""


class UserNotFoundError(UserServiceError):
    """Raised when the target user does not exist."""


class InactiveUserError(UserServiceError):
    """Raised when an inactive user attempts a self-service operation."""


class CurrentPasswordMismatchError(UserServiceError):
    """Raised when the supplied current password does not match the stored one."""


class UserService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.admin_activity_logger = self.cfg.config.get("admin_activity_logger")

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('user_command')
        logger.verbose("Handling user command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_user,
            "enable": self._enable_user,
            "disable": self._disable_user,
            "get": self._get_user,
            "list": self._list_users,
            "password-change": self._change_user_password
        }

        handler = handlers.get(command)
        if handler is not None:
            action = normalize_admin_activity_action(command)
            try:
                handler()
                self._log_admin_activity(command=action, outcome="success")
            except Exception as exc:
                self._log_admin_activity(command=action, outcome="failed", error=str(exc))
                raise
        else:
            logger.error("Invalid user command received: %s", command)

    def _log_admin_activity(self, command: str | None, outcome: str, error: str | None = None) -> None:
        if command is None or self.admin_activity_logger is None:
            return
        self.admin_activity_logger.log_activity(
            interface="cli",
            entity="user",
            action=command,
            outcome=outcome,
            target={
                "user_id": self.cfg.config["parameters"].get("user_id"),
                "username": self.cfg.config["parameters"].get("username"),
            },
            error=error,
        )

    def _add_user(self) -> None:
        username = self.cfg.config["parameters"]["username"]
        password = self.cfg.config["parameters"]["user_password"]
        email = self.cfg.config["parameters"]["user_email"]
        role = self.cfg.config["parameters"]["user_role"]

        password_hash = Passwords.hash(password)

        user = User(id=None, username=username, password_hash=password_hash, email=email, role=role, is_active=True, created_at=None, updated_at=None)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.user_add(user)

    def _enable_user(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['username']
        if user_id is not None:
            db_service.user_enable_by_id(user_id)
            return
        if username is not None:
            db_service.user_enable_by_username(username)
            return

        raise ValueError(
            "User id or username must be provided"
        )

    def _disable_user(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['username']
        if user_id is not None:
            db_service.user_disable_by_id(user_id)
            return
        if username is not None:
            db_service.user_disable_by_username(username)
            return

        raise ValueError(
            "User id or username must be provided"
        )

    def _get_user(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['username']
        if user_id is not None:
            user = db_service.user_get_by_id(user_id)
        elif username is not None:
            user = db_service.user_get_by_username(username)
        else:
            raise ValueError(
                "User id or username must be provided"
            )
        if user is not None:
            logger.info("User found: %s", user)
        else:
            logger.info("User not found")

    def _list_users(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_record = self.cfg.config["parameters"].get("user_record", False)
        user_status = self.cfg.config["parameters"].get("user_status")
        is_active = None if user_status is None else user_status == "enabled"

        if user_record:
            users = db_service.user_get_record(is_active=is_active)
        else:
            users = db_service.user_get_list(is_active=is_active)

        if users:
            logger.info("\n%s", UserFormatter.format_list(users))
        else:
            logger.info("No users found")

    # Password management (shared by the CLI and the REST API)

    def _password_policy(self) -> PasswordPolicy:
        return PasswordPolicy.from_mapping(self.cfg.config.get("parameters"))

    def _require_user(self, user_id: int) -> User:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user = db_service.user_get_by_id(user_id)
        if user is None:
            raise UserNotFoundError(f"User id={user_id} not found")
        return user

    def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str,
        confirm_password: str,
    ) -> None:
        """Self-service password change; requires the current password.

        Raises:
            UserNotFoundError: the user does not exist.
            InactiveUserError: the user is not active.
            CurrentPasswordMismatchError: the current password is wrong.
            PasswordPolicyError: the new password or confirmation is invalid.
        """
        user = self._require_user(user_id)
        if not user.is_active:
            raise InactiveUserError(f"User id={user_id} is inactive")
        if not Passwords.verify(current_password, user.password_hash):
            raise CurrentPasswordMismatchError("Current password is incorrect")

        self._password_policy().validate_with_confirmation(new_password, confirm_password)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.user_set_password_by_id(user_id, Passwords.hash(new_password))

    def reset_password(
        self,
        user_id: int,
        new_password: str,
        confirm_password: str,
    ) -> None:
        """Administrative password reset; the current password is not required.

        Inactive users may be reset: resetting a password never activates,
        deactivates, or otherwise modifies the user account.

        Raises:
            UserNotFoundError: the user does not exist.
            PasswordPolicyError: the new password or confirmation is invalid.
        """
        self._require_user(user_id)

        self._password_policy().validate_with_confirmation(new_password, confirm_password)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.user_set_password_by_id(user_id, Passwords.hash(new_password))

    def _change_user_password(self) -> None:
        """CLI handler: administrative password reset with secure prompts.

        Passwords are read interactively with getpass and are never accepted
        as command-line arguments, displayed, or logged.
        """
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]["user_id"]
        username = self.cfg.config["parameters"]["username"]

        user = None
        if user_id is not None:
            user = db_service.user_get_by_id(user_id)
        elif username is not None:
            user = db_service.user_get_by_username(username)
        else:
            raise ValueError(
                "User id or username must be provided"
            )

        if user is None:
            raise UserNotFoundError(
                f"User id={user_id} not found" if user_id is not None
                else f"User username='{username}' not found"
            )

        # keep the resolved id so the admin activity log records it
        self.cfg.config["parameters"]["user_id"] = user.id

        new_password = getpass.getpass("New password: ")
        confirm_password = getpass.getpass("Confirm new password: ")

        self.reset_password(user.id, new_password, confirm_password)
        logger.info("Password updated for user '%s' (id=%s)", user.username, user.id)
