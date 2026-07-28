# users_interface.py

from typing import Protocol

class UserInterface(Protocol):

    def add_user(self, name: str, email: str) -> int:
        ...

    def get_user(self, user_id: int) -> dict | None:
        ...

    def update_user(self, user_id: int, name: str, email: str) -> bool:
        ...

    def delete_user(self, user_id: int) -> bool:
        ...
