# core/data_models.py

from typing import Any, Dict, Optional
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path

from ota_http_server.core.config import Config
from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

# return type of .auth_service.create_device_token
@dataclass
class TokenResult:
    token: str
    payload: Dict[str, Any]

@dataclass
class CommandResult:
    success: bool
    message: str
    data: Any = None

@dataclass(frozen=True)
class Column:
    title: str
    width: int
    align: str = "<"

@dataclass
class User:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    username: str       # should be unique in the database.
    password_hash: str  # store only a hash (for example bcrypt or Argon2), never the plaintext password.
    email: str          # email of the user
    role: str           # allows role-based access control later (admin, operator, viewer).
    is_active: bool     # lets you disable a user account without deleting its audit history.
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # useful for auditing and future administration features.

    def __str__(self) -> str:
        status = "active" if self.is_active else "disabled"

        created_at = (
            self.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.created_at
            else "-"
        )

        updated_at = (
            self.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.updated_at
            else "-"
        )
        return (
            f"User("
            f"ID:{self.id}, "
            f"username:{self.username}, "
            f"email:{self.email}, "
            f"role:{self.role}, "
            f"status:{status}, "
            f"created_at:{created_at}, "
            f"updated_at:{updated_at}"
            f")"
        )

@dataclass
class Project:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    name: str           # Unique project name, e.g. smart_air
    display_name: str   # Human-readable name
    description: str    # Optional description
    created_by: int     # FK → Users: Who created the project
    is_active: bool     # Archive/disable project
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # Audit information

    def __str__(self) -> str:
        status = "active" if self.is_active else "disabled"

        created_at = (
            self.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.created_at
            else "-"
        )

        updated_at = (
            self.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.updated_at
            else "-"
        )

        return (
            f"Project("
            f"ID:{self.id}, "
            f"name:{self.name}, "
            f"display_name:{self.display_name}, "
            f"description:{self.description}, "
            f"status:{status}, "
            f"created_at:{created_at}, "
            f"updated_at:{updated_at}"
            f")"
        )

@dataclass
class Device:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    uuid: str           # Unique hardware identifier (UUIDv4)
    project_id: int     # FK → Projects: Which project this device belongs to
    model: str          # Hardware model, e.g. ESP32S3
    serial_number: str  # Optional manufacturing serial
    current_version: str    # Current firmware version
    last_seen: Optional[datetime]   # Last contact with server
    is_active: bool     # Disable OTA for this device
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # Audit information

    def __str__(self) -> str:
        status = "active" if self.is_active else "disabled"

        last_seen = (
            self.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            if self.last_seen
            else "-"
        )

        created_at = (
            self.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.created_at
            else "-"
        )

        updated_at = (
            self.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.updated_at
            else "-"
        )

        return (
            f"Device("
            f"ID:{self.id}, "
            f"uuid:{self.uuid}, "
            f"project_id:{self.project_id}, "
            f"model:{self.model}, "
            f"serial_number:{self.serial_number}, "
            f"current_version:{self.current_version}, "
            f"last_seen:{last_seen}, "
            f"is_active:{self.is_active}, "
            f"created_at:{created_at}, "
            f"updated_at:{updated_at}"
            f")"
        )

@dataclass
class Firmware:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    project_id: int     # FK → Projects: Which project owns this firmware
    version: str        # e.g. 02.00.01
    filename: str       # Stored binary filename
    file_size: int      # Bytes
    checksum: str       # SHA-256 hash
    release_notes: str  # Optional notes
    channel: str        # stable, beta, dev
    is_active: bool     # Disable OTA for this firmware
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # Audit information

    def __str__(self) -> str:
        created_at = (
            self.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.created_at
            else "-"
        )

        updated_at = (
            self.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.updated_at
            else "-"
        )

        return(
            f"Firmware("
            f"ID:{self.id}, "
            f"version:{self.version}, "
            f"filename:{self.filename}, "
            f"file_size:{self.file_size}, "
            f"checksum:{self.checksum}, "
            f"release_notes:{self.release_notes}, "
            f"channel:{self.channel}, "
            f"is_active:{self.is_active}, "
            f"created_at:{created_at}, "
            f"updated_at:{updated_at}"
            f")"
        )

@dataclass
class FirmwareListItem:
    id: int
    project_name: str
    version: str
    filename: str
    file_size: int
    channel: str

class AppPaths:
    def __init__(self, cfg: Config):
        self._cfg = cfg
        self.app_data_dir = Path(self._cfg.config["parameters"]["app_directory"]).expanduser().resolve()
        self.ensure_directories()

    @property
    def database_sqlite(self) -> Path:
        return self.app_data_dir / self._cfg.config["database"]["sqlite"]["db_file"]

    @property
    def logs_dir(self) -> Path:
        return self.app_data_dir / "logs"

    @property
    def www_dir(self) -> Path:
        return self.app_data_dir / self._cfg.config["parameters"]["www_dir"]

    @property
    def firmware_dir(self) -> Path:
        return self.www_dir / self._cfg.config["parameters"]["firmware_dir"]

    def project_dir(self,project) -> Path:
        return self.firmware_dir / project

    def ensure_directories(self) -> None:
        """Create all required application directories."""

        if self.app_data_dir.exists() and not self.app_data_dir.is_dir():
            raise RuntimeError(f"{self.app_data_dir} exists but is not a directory.")
        try:
            self.app_data_dir.mkdir(parents=True, exist_ok=True)
            logger.verbose(f"Ensured %s",self.app_data_dir)
        except OSError as e:
            logger.error("Cannot create application data directory '%s': %s",self.app_data_dir,e)
            raise

        try:
            self.www_dir.mkdir(exist_ok=True)
            logger.verbose(f"Ensured %s",self.www_dir)
        except:
            logger.error("Cannot create application data directory '%s': %s",self.www_dir,e)
            raise

        try:
            self.logs_dir.mkdir(exist_ok=True)
            logger.verbose("Ensured %s",self.logs_dir)
        except:
            logger.error("Cannot create application data directory '%s': %s",self.logs_dir,e)
            raise
