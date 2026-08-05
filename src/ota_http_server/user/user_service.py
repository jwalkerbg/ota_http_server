# user_service.py

from ota_http_server.core.config import Config
from ota_http_server.user.user_interface import UserInterface
from ota_http_server.core.passwords import Passwords
from ota_http_server.core.data_models import User
from ota_http_server.database.database_service import DatabaseService
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class UserService:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # CLI command handler for user operations

    def command_handler(self) -> None:
        logger.info("Handling database command: %s", self.cfg.config.get('user_command'))
        command = self.cfg.config.get('user_command')

        handlers= {
            "add": self.add_user,
            "enable": self.enable_user,
            "disable": self.disable_user,
            "get": self.get_user,
            "list": self.list_users
        }

        handler = handlers.get(command)
        if handler is not None:
            handler()
        else:
            logger.debug("Invalid user command received: %s", command)

    def add_user(self) -> None:
        username = self.cfg.config["parameters"]["username"]
        password = self.cfg.config["parameters"]["user_password"]
        email = self.cfg.config["parameters"]["user_email"]
        role = self.cfg.config["parameters"]["user_role"]

        password_hash = Passwords.hash(password)

        user = User(id=None, username=username, password_hash=password_hash, email=email, role=role, is_active=True, created_at=None, updated_at=None)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.add_user(user)

    def enable_user(self) -> None:
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

    def disable_user(self) -> None:
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

    def get_user(self) -> None:
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

    def list_users(self) -> None:
        db_service: DatabaseService = self.cfg.config["db_service"]
        users = db_service.user_get_list()
        if users:
            header = (
                f"{'ID':<5}"
                f"{'Username':<20}"
                f"{'Email':<30}"
                f"{'Role':<12}"
                f"{'Status':<10}"
                f"{'Created At':<22}"
                f"{'Updated At':<22}"
            )
            separator = "-" * len(header)
            logger.verbose(header)
            logger.verbose(separator)
            for user in users:
                logger.verbose("%s", user)
        else:
            logger.verbose("No users found")

    # REST API methods for user operations can be added here, e.g., create_user, get_user, update_user, delete_user, etc.

    # placeholder for future REST API methods
