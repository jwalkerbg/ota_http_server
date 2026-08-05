# core/formatters.py

from datetime import datetime
from ota_http_server.user.user_service import User

class UserFormatter:

    ID_WIDTH =  5
    USERNAME_WIDTH =  20
    EMAIL_WIDTH =  30
    ROLE_WIDTH =  12
    STATUS_WIDTH =  10
    DATE_WIDTH =  22

    @classmethod
    def header(cls) -> str:
        return (
            f"{'ID':<{cls.ID_WIDTH}}"
            f"{'Username':<{cls.USERNAME_WIDTH}}"
            f"{'Email':<{cls.EMAIL_WIDTH}}"
            f"{'Role':<{cls.ROLE_WIDTH}}"
            f"{'Status':<{cls.STATUS_WIDTH}}"
            f"{'Created At':<{cls.DATE_WIDTH}}"
            f"{'Updated At':<{cls.DATE_WIDTH}}"
        )

    @classmethod
    def separator(cls) -> str:
        return "-" * len(cls.header())

    @classmethod
    def format(cls, user: User) -> str:
        status = "active" if user.is_active else "disabled"

        created = (
            user.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if user.created_at
            else "-"
        )

        updated = (
            user.updated_at.strftime("%Y-%m-%d %H:%M:%S")
            if user.updated_at
            else "-"
        )

        return (
            f"{user.id:<{cls.ID_WIDTH}}"
            f"{user.username:<{cls.USERNAME_WIDTH}}"
            f"{user.email:<{cls.EMAIL_WIDTH}}"
            f"{user.role:<{cls.ROLE_WIDTH}}"
            f"{status:<{cls.STATUS_WIDTH}}"
            f"{created:<{cls.DATE_WIDTH}}"
            f"{updated:<{cls.DATE_WIDTH}}"
        )