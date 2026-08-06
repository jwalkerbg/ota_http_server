# user_service.py

from ota_http_server.core.config import Config
from ota_http_server.core.passwords import Passwords
from ota_http_server.core.data_models import User
from ota_http_server.core.formatters import UserFormatter
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class UserService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # CLI command handler for user operations

    def command_handler(self) -> None:
        command = self.cfg.config.get('user_command')
        logger.info("Handling user command: %s", command)

        # these handlers expect their parameters in self.cfg.config
        handlers= {
            "add": self._add_user,
            "enable": self._enable_user,
            "disable": self._disable_user,
            "get": self._get_user,
            "list": self._list_users
        }

        handler = handlers.get(command)
        if handler is not None:
            handler()
        else:
            logger.debug("Invalid user command received: %s", command)

    def _add_user(self) -> None:
        username = self.cfg.config["parameters"]["username"]
        password = self.cfg.config["parameters"]["user_password"]
        email = self.cfg.config["parameters"]["user_email"]
        role = self.cfg.config["parameters"]["user_role"]

        password_hash = Passwords.hash(password)

        user = User(id=None, username=username, password_hash=password_hash, email=email, role=role, is_active=True, created_at=None, updated_at=None)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.add_user(user)

    def _enable_user(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['username']
        if user_id is not None:
            db_service.enable_user_by_id(user_id)
            return
        if username is not None:
            db_service.enable_user_by_username(username)
            return

        raise ValueError(
            "User id or username must be provided"
        )

    def _disable_user(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['username']
        if user_id is not None:
            db_service.disable_user_by_id(user_id)
            return
        if username is not None:
            db_service.disable_user_by_username(username)
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
            logger.verbose("User found: %s", user)
        else:
            logger.verbose("User not found")

    def _list_users(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        users = db_service.user_get_list()
        if users:
            logger.verbose("\n%s",UserFormatter.format_list(users))
        else:
            logger.verbose("No users found")

    # REST API methods for user operations can be added here, e.g., create_user, get_user, update_user, delete_user, etc.

    # placeholder for future REST API methods
