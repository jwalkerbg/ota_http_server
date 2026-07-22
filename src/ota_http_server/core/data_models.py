# core/data_models.py

from typing import Any, Dict, Optional
from datetime import datetime
from dataclasses import dataclass

# return type of .auth_service.create_device_token
@dataclass
class TokenResult:
    token: str
    payload: Dict[str, Any]

@dataclass
class User:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    username: str       # should be unique in the database.
    password_hash: str  # store only a hash (for example bcrypt or Argon2), never the plaintext password.
    role: str           # allows role-based access control later (admin, operator, viewer).
    is_active: bool     # lets you disable a user account without deleting its audit history.
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # useful for auditing and future administration features.

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

@dataclass
class Device:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    device_id: str      # Unique hardware identifier (UUIDv4)
    project_id: int     # FK → Projects: Which project this device belongs to
    model: str          # Hardware model, e.g. ESP32S3
    serial_number: str  # Optional manufacturing serial
    current_version: str    # Current firmware version
    last_seen: Optional[datetime]   # Last contact with server
    is_active: bool     # Disable OTA for this device
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # Audit information

@dataclass
class Firmware:
    id: Optional[int]   # the database primary key. It is None before the object is inserted into SQLite.
    project_id: int     # FK → Projects: Which project owns this firmware
    version: str        # e.g. 02.00.01
    filename: str       # Stored binary filename
    file_size: int      # Bytes
    checksum: str       # SHA-256 hash
    release_notes: str  # Optional notes
    channel: str        # stable, beta, dev (*)this an example)
    created_at: Optional[datetime]
    updated_at: Optional[datetime]  # Audit information
