"""mypool_size handling of the MySQL service.

Pool construction tests use a fake pool class; the exhaustion test needs a real
server and is skipped unless OTA_TEST_MYSQL_* variables are set.
"""

import os
from types import SimpleNamespace

import pytest
from mysql.connector.errors import PoolError
from mysql.connector.pooling import CNX_POOL_MAXSIZE

from ota_http_server.database import db_mysql_service as m


def _cfg(pool_size, **overrides):
    mysql_cfg = {
        "myhost": "h", "myport": 3306, "mydatabase": "d", "myuser": "u",
        "mypassword": "p", "myecho": False, "mypool_size": pool_size, "migrations_dir": "unused",
        **overrides,
    }
    return SimpleNamespace(config={
        "parameters": {"trace_sql": False},
        "database": {"mysql": mysql_cfg},
    })


@pytest.fixture()
def fake_pool(monkeypatch):
    created = []

    class FakePool:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            created.append(self)

        def get_connection(self):
            return object()

    monkeypatch.setattr(m, "MySQLConnectionPool", FakePool)
    return created


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        (5, 5),
        ("7", 7),
        (1, 1),
        (0, 1),
        (-3, 1),
        (CNX_POOL_MAXSIZE, CNX_POOL_MAXSIZE),
        (CNX_POOL_MAXSIZE + 100, CNX_POOL_MAXSIZE),
    ],
)
def test_pool_size_is_clamped(fake_pool, configured, expected):
    service = m.DatabaseMySQLService(_cfg(configured))

    service._get_pool()

    assert fake_pool[0].kwargs["pool_size"] == expected


def test_pool_is_created_lazily_and_reused(fake_pool):
    service = m.DatabaseMySQLService(_cfg(3))
    assert fake_pool == []

    first = service._get_pool()
    second = service._get_pool()

    assert first is second
    assert len(fake_pool) == 1


def test_pool_receives_connection_settings(fake_pool):
    service = m.DatabaseMySQLService(_cfg(3))

    service._get_pool()

    kwargs = fake_pool[0].kwargs
    assert kwargs["host"] == "h"
    assert kwargs["port"] == 3306
    assert kwargs["database"] == "d"
    assert kwargs["user"] == "u"
    assert kwargs["password"] == "p"
    assert kwargs["autocommit"] is False


@pytest.mark.skipif(
    not all(os.environ.get(k) for k in (
        "OTA_TEST_MYSQL_HOST", "OTA_TEST_MYSQL_DB",
        "OTA_TEST_MYSQL_USER", "OTA_TEST_MYSQL_PASSWORD",
    )),
    reason="OTA_TEST_MYSQL_* environment variables are not set",
)
def test_pool_size_limits_concurrent_connections():
    cfg = _cfg(
        2,
        myhost=os.environ["OTA_TEST_MYSQL_HOST"],
        myport=int(os.environ.get("OTA_TEST_MYSQL_PORT", "3306")),
        mydatabase=os.environ["OTA_TEST_MYSQL_DB"],
        myuser=os.environ["OTA_TEST_MYSQL_USER"],
        mypassword=os.environ["OTA_TEST_MYSQL_PASSWORD"],
    )
    service = m.DatabaseMySQLService(cfg)

    first = service._connect()
    second = service._connect()
    with pytest.raises(PoolError):
        service._connect()

    first.close()  # returns the connection to the pool
    third = service._connect()
    cursor = third.cursor()
    cursor.execute("SELECT 1")
    assert cursor.fetchone() == (1,)

    second.close()
    third.close()
