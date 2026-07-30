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

    def command_handler(self):
        logger.info("Handling database command: %s", self.cfg.config.get('user_command'))
        command = self.cfg.config.get('user_command')

        if command == "add":
            self.add_user()
        elif command == "enable":
            self.enable_user()
        elif command == "disable":
            self.disable_user()
        else:
            logger.debug("Invalid user command received: %s", command)

    def add_user(self):
        username = self.cfg.config["parameters"]["user_name"]
        password = self.cfg.config["parameters"]["user_password"]
        email = self.cfg.config["parameters"]["user_email"]
        role = self.cfg.config["parameters"]["user_role"]

        password_hash = Passwords.hash(password)

        user = User(id=None, username=username, password_hash=password_hash, email=email, role=role, is_active=True, created_at=None, updated_at=None)

        db_service: DatabaseService = self.cfg.config["db_service"]
        db_service.add_user(user)

    def enable_user(self):
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['user_name']
        if user_id is not None:
            db_service.enable_user_by_id(user_id)
            return
        if username is not None:
            db_service.enable_user_by_username(username)
            return

        raise ValueError(
            "User id or username must be provided"
        )

    def disable_user(self):
        db_service: DatabaseService = self.cfg.config["db_service"]
        user_id = self.cfg.config["parameters"]['user_id']
        username = self.cfg.config['parameters']['user_name']
        if user_id is not None:
            db_service.disable_user_by_id(user_id)
            return
        if username is not None:
            db_service.disable_user_by_username(username)
            return

        raise ValueError(
            "User id or username must be provided"
        )
