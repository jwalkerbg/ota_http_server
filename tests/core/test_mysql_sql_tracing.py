from unittest.mock import MagicMock

from ota_http_server.database.mysql_sql_tracing import (
    SQLTracingMySQLConnection,
    is_sql_tracing_enabled,
    with_mysql_sql_tracing,
)


class DummyCursor:
    def __init__(self):
        self.calls = []

    def execute(self, operation, params=None, *args, **kwargs):
        self.calls.append(("execute", operation, params, args, kwargs))
        return "ok"

    def executemany(self, operation, seq_params, *args, **kwargs):
        self.calls.append(("executemany", operation, seq_params, args, kwargs))
        return "many"


class DummyConnection:
    def __init__(self):
        self._cursor = DummyCursor()

    def cursor(self, *args, **kwargs):
        return self._cursor


def test_is_sql_tracing_enabled_parses_boolean_like_values():
    assert is_sql_tracing_enabled(True, False)
    assert is_sql_tracing_enabled(False, "true")
    assert is_sql_tracing_enabled("1", False)
    assert not is_sql_tracing_enabled(False, "false")
    assert not is_sql_tracing_enabled(False, None)


def test_with_mysql_sql_tracing_wraps_connection_when_enabled():
    conn = DummyConnection()
    logger = MagicMock()

    wrapped = with_mysql_sql_tracing(conn, logger, True)

    assert isinstance(wrapped, SQLTracingMySQLConnection)


def test_wrapped_cursor_logs_and_executes_sql():
    conn = DummyConnection()
    logger = MagicMock()
    wrapped = with_mysql_sql_tracing(conn, logger, True)
    cursor = wrapped.cursor()

    result = cursor.execute("SELECT * FROM users WHERE id = %s", (7,))

    assert result == "ok"
    logger.debug.assert_called_with(
        "SQL: %s | params: %s",
        "SELECT * FROM users WHERE id = %s",
        (7,),
    )
