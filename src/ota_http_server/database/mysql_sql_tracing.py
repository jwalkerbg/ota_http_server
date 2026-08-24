import logging
from typing import Any


def is_sql_tracing_enabled(trace_sql: Any, db_echo: Any) -> bool:
    return _as_bool(trace_sql) or _as_bool(db_echo)


def with_mysql_sql_tracing(conn: Any, logger: logging.Logger, enabled: bool) -> Any:
    if not enabled:
        return conn
    return SQLTracingMySQLConnection(conn, logger)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


class SQLTracingMySQLCursor:
    def __init__(self, cursor: Any, logger: logging.Logger):
        self._cursor = cursor
        self._logger = logger

    def execute(self, operation: str, params: Any = None, *args: Any, **kwargs: Any) -> Any:
        self._log_sql(operation, params)
        if params is None:
            return self._cursor.execute(operation, *args, **kwargs)
        return self._cursor.execute(operation, params, *args, **kwargs)

    def executemany(self, operation: str, seq_params: Any, *args: Any, **kwargs: Any) -> Any:
        self._logger.debug("SQL: %s | executemany", operation)
        return self._cursor.executemany(operation, seq_params, *args, **kwargs)

    def _log_sql(self, operation: str, params: Any = None) -> None:
        if params is None:
            self._logger.debug("SQL: %s", operation)
            return
        self._logger.debug("SQL: %s | params: %s", operation, params)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._cursor, item)

    def __iter__(self):
        return iter(self._cursor)

    def __enter__(self):
        if hasattr(self._cursor, "__enter__"):
            self._cursor.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if hasattr(self._cursor, "__exit__"):
            return self._cursor.__exit__(exc_type, exc, tb)
        self._cursor.close()
        return False


class SQLTracingMySQLConnection:
    def __init__(self, conn: Any, logger: logging.Logger):
        self._conn = conn
        self._logger = logger

    def cursor(self, *args: Any, **kwargs: Any) -> SQLTracingMySQLCursor:
        return SQLTracingMySQLCursor(self._conn.cursor(*args, **kwargs), self._logger)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._conn, item)

    def __enter__(self):
        if hasattr(self._conn, "__enter__"):
            self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if hasattr(self._conn, "__exit__"):
            return self._conn.__exit__(exc_type, exc, tb)
        self._conn.close()
        return False
