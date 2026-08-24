from ota_http_server.core.data_models import Column, Target
from ota_http_server.core.formatters import TableFormatter


class TargetFormatter:
    ID_WIDTH = 5
    NAME_WIDTH = 32

    COLUMNS = [
        Column("ID", ID_WIDTH, ">"),
        Column("Name", NAME_WIDTH, "^"),
    ]

    @classmethod
    def format(cls, target: Target) -> list[str]:
        values = [
            str(target.id),
            target.name,
        ]
        return TableFormatter.format_row(values, cls.COLUMNS)

    @classmethod
    def format_list(cls, items: list[Target]) -> str:
        lines = [
            TableFormatter.header(cls.COLUMNS),
            TableFormatter.separator(cls.COLUMNS),
        ]
        for item in items:
            lines.extend(cls.format(item))
        return "\n".join(lines)
