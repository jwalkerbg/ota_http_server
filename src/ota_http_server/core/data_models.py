# core/data_models.py

from typing import Any, Dict
from dataclasses import dataclass

# return type of .auth_service.create_device_token
@dataclass
class TokenResult:
    token: str
    payload: Dict[str, Any]

