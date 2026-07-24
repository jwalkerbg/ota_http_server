# core/db.py

import traceback

from ota_http_server.core.config import Config
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

class DatabaseService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.conn = None

    def db_command_handler(self) -> None:
        logger.info("Handling database command: %s", self.cfg.config.get('db_command'))
        db_command = self.cfg.config.get('db_command')

        conn = None

        if db_command == 'init-db':
            db_file = self.cfg.config['parameters']['ota_db']
            self.init_db()
        elif db_command == 'create-user':
            email = self.cfg.config['parameters']['email']
            self.create_user(email)
        elif db_command == 'create-device':
            device_name = self.cfg.config['parameters']['device_name']
            device_uuid = self.cfg.config['parameters']['device_uuid']
            self.create_device(device_name, device_uuid)
        elif db_command == 'create-project':
            project_name = self.cfg.config['parameters']['project_name']
            project_uuid = self.cfg.config['parameters']['project_uuid']
            project_path = self.cfg.config['parameters']['project_path']
            self.create_project(project_name, project_uuid, project_path)

    def init_db(self) -> None:
        try:
            # Here you would add the actual database initialization logic, e.g. creating tables, etc.
            logger.info("Initializing database")
            # For example, if using SQLAlchemy, you would create the engine and call Base.metadata.create_all(engine)
            # This is just a placeholder to indicate where the real implementation would go.
            logger.info("Database initialized")
        except Exception as e:
            logger.error("Error initializing database: %s", str(e))
            traceback.print_exc()

    def create_user(self, email:str) -> None:
        try:
            # Here you would add the actual logic to create a user in the database
            logger.info("Creating user with email: %s (this is a placeholder implementation)", email)
        except Exception as e:
            logger.error("Error creating user: %s", str(e))
            traceback.print_exc()

    def create_device(self,device_name:str, device_uuid:str) -> None:
        try:
            # Here you would add the actual logic to create a device in the database
            logger.info("Creating device with name: %s and UUID: %s (this is a placeholder implementation)", device_name, device_uuid)
        except Exception as e:
            logger.error("Error creating device: %s", str(e))
            traceback.print_exc()

    def create_project(self, project_name:str, project_uuid:str, project_path:str) -> None:
        try:
            # Here you would add the actual logic to create a project in the database
            logger.info("Creating project with name: %s, UUID: %s, and path: %s (this is a placeholder implementation)", project_name, project_uuid, project_path)
        except Exception as e:
            logger.error("Error creating project: %s", str(e))
            traceback.print_exc()
