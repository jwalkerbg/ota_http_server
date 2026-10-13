"""Unit and integration tests for abstract database SSL configuration and mappings."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from ota_http_server.core.config import Config
from ota_http_server.database.db_ssl import (
    DatabaseSSLConfig,
    SSLMode,
    get_mysql_ssl_kwargs,
    get_postgres_ssl_kwargs,
    normalize_ssl_mode,
)

CERTSD_DIR = Path(__file__).parents[2] / "certsd"
CA_CERT_PATH = str(CERTSD_DIR / "ca_cert.pem")
CLIENT_CERT_PATH = str(CERTSD_DIR / "client_cert.pem")
CLIENT_KEY_PATH = str(CERTSD_DIR / "client_key.pem")


class TestSSLNormalization:
    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            (None, SSLMode.DISABLED),
            ("", SSLMode.DISABLED),
            ("   ", SSLMode.DISABLED),
            ("disabled", SSLMode.DISABLED),
            ("disable", SSLMode.DISABLED),
            ("off", SSLMode.DISABLED),
            ("false", SSLMode.DISABLED),
            ("none", SSLMode.DISABLED),
            ("prefer", SSLMode.PREFER),
            ("preferred", SSLMode.PREFER),
            ("PREFER", SSLMode.PREFER),
            ("required", SSLMode.REQUIRED),
            ("require", SSLMode.REQUIRED),
            ("REQUIRED", SSLMode.REQUIRED),
            ("on", SSLMode.REQUIRED),
            ("true", SSLMode.REQUIRED),
            ("verify_ca", SSLMode.VERIFY_CA),
            ("verify-ca", SSLMode.VERIFY_CA),
            ("VERIFY-CA", SSLMode.VERIFY_CA),
            ("verify_full", SSLMode.VERIFY_FULL),
            ("verify-full", SSLMode.VERIFY_FULL),
            ("verify_identity", SSLMode.VERIFY_FULL),
            ("verify-identity", SSLMode.VERIFY_FULL),
            ("VERIFY_FULL", SSLMode.VERIFY_FULL),
            (SSLMode.VERIFY_FULL, SSLMode.VERIFY_FULL),
        ],
    )
    def test_normalize_valid_modes(self, input_val, expected):
        assert normalize_ssl_mode(input_val) == expected

    @pytest.mark.parametrize(
        "invalid_mode",
        [
            "invalid_mode",
            "strict",
            "123",
            "yes",
        ],
    )
    def test_normalize_invalid_mode_raises(self, invalid_mode):
        with pytest.raises(ValueError, match="Invalid ssl_mode"):
            normalize_ssl_mode(invalid_mode)


class TestDatabaseSSLConfigValidation:
    def test_default_config_is_disabled(self):
        cfg = DatabaseSSLConfig.from_dict({})
        assert cfg.ssl_mode == SSLMode.DISABLED
        assert cfg.ssl_ca is None
        assert cfg.ssl_cert is None
        assert cfg.ssl_key is None

    def test_none_config_is_disabled(self):
        cfg = DatabaseSSLConfig.from_dict(None)
        assert cfg.ssl_mode == SSLMode.DISABLED

    @pytest.mark.parametrize("mode", ["verify_ca", "verify-ca", "verify_full", "verify-full"])
    def test_verify_modes_require_ca(self, mode):
        with pytest.raises(ValueError, match="ssl_ca must be provided"):
            DatabaseSSLConfig.from_dict({"ssl_mode": mode})

        with pytest.raises(ValueError, match="ssl_ca must be provided"):
            DatabaseSSLConfig.from_dict({"ssl_mode": mode, "ssl_ca": ""})

    def test_client_cert_without_key_raises(self):
        with pytest.raises(ValueError, match="Both ssl_cert and ssl_key must be specified"):
            DatabaseSSLConfig.from_dict({
                "ssl_mode": "prefer",
                "ssl_cert": "client.crt",
                "ssl_key": None,
            })

    def test_client_key_without_cert_raises(self):
        with pytest.raises(ValueError, match="Both ssl_cert and ssl_key must be specified"):
            DatabaseSSLConfig.from_dict({
                "ssl_mode": "prefer",
                "ssl_cert": "",
                "ssl_key": "client.key",
            })


class TestMySQLKwargsMapping:
    def test_disabled(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "disabled"})
        assert kwargs == {"ssl_disabled": True}

    def test_prefer(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "prefer"})
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": False,
            "ssl_verify_identity": False,
        }

    def test_prefer_with_ca(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "prefer", "ssl_ca": "ca.pem"})
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": False,
            "ssl_verify_identity": False,
            "ssl_ca": "ca.pem",
        }

    def test_required(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "required"})
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": False,
            "ssl_verify_identity": False,
        }

    def test_required_with_ca(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "required", "ssl_ca": "ca.pem"})
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": False,
            "ssl_verify_identity": False,
            "ssl_ca": "ca.pem",
        }

    def test_verify_ca(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "verify_ca", "ssl_ca": "ca.pem"})
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": True,
            "ssl_verify_identity": False,
            "ssl_ca": "ca.pem",
        }

    def test_verify_full(self):
        kwargs = get_mysql_ssl_kwargs({"ssl_mode": "verify_full", "ssl_ca": "ca.pem"})
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": True,
            "ssl_verify_identity": True,
            "ssl_ca": "ca.pem",
        }

    def test_mtls_client_certificates(self):
        kwargs = get_mysql_ssl_kwargs({
            "ssl_mode": "verify_full",
            "ssl_ca": "ca.pem",
            "ssl_cert": "client.crt",
            "ssl_key": "client.key",
        })
        assert kwargs == {
            "ssl_disabled": False,
            "ssl_verify_cert": True,
            "ssl_verify_identity": True,
            "ssl_ca": "ca.pem",
            "ssl_cert": "client.crt",
            "ssl_key": "client.key",
        }


class TestPostgreSQLKwargsMapping:
    def test_disabled(self):
        kwargs = get_postgres_ssl_kwargs({"ssl_mode": "disabled"})
        assert kwargs == {"sslmode": "disable"}

    def test_prefer(self):
        kwargs = get_postgres_ssl_kwargs({"ssl_mode": "prefer"})
        assert kwargs == {"sslmode": "prefer"}

    def test_prefer_with_ca(self):
        kwargs = get_postgres_ssl_kwargs({"ssl_mode": "prefer", "ssl_ca": "ca.pem"})
        assert kwargs == {"sslmode": "prefer", "sslrootcert": "ca.pem"}

    def test_required(self):
        kwargs = get_postgres_ssl_kwargs({"ssl_mode": "required"})
        assert kwargs == {"sslmode": "require"}

    def test_verify_ca(self):
        kwargs = get_postgres_ssl_kwargs({"ssl_mode": "verify_ca", "ssl_ca": "ca.pem"})
        assert kwargs == {"sslmode": "verify-ca", "sslrootcert": "ca.pem"}

    def test_verify_full(self):
        kwargs = get_postgres_ssl_kwargs({"ssl_mode": "verify_full", "ssl_ca": "ca.pem"})
        assert kwargs == {"sslmode": "verify-full", "sslrootcert": "ca.pem"}

    def test_mtls_client_certificates(self):
        kwargs = get_postgres_ssl_kwargs({
            "ssl_mode": "verify_full",
            "ssl_ca": "ca.pem",
            "ssl_cert": "client.crt",
            "ssl_key": "client.key",
        })
        assert kwargs == {
            "sslmode": "verify-full",
            "sslrootcert": "ca.pem",
            "sslcert": "client.crt",
            "sslkey": "client.key",
        }


class TestConfigIntegration:
    def test_env_variables_loading(self, monkeypatch):
        monkeypatch.setenv("OTA_MY_SSL_MODE", "verify_full")
        monkeypatch.setenv("OTA_MY_SSL_CA", "/path/to/my_ca.pem")
        monkeypatch.setenv("OTA_MY_SSL_CERT", "/path/to/my_cert.pem")
        monkeypatch.setenv("OTA_MY_SSL_KEY", "/path/to/my_key.pem")
        monkeypatch.setenv("OTA_PG_SSL_MODE", "verify_ca")
        monkeypatch.setenv("OTA_PG_SSL_CA", "/path/to/pg_ca.pem")
        monkeypatch.setenv("OTA_PG_SSL_CERT", "/path/to/pg_cert.pem")
        monkeypatch.setenv("OTA_PG_SSL_KEY", "/path/to/pg_key.pem")

        cfg = Config()
        cfg.load_config_env()

        my_cfg = cfg.config["database"]["mysql"]
        assert my_cfg["ssl_mode"] == "verify_full"
        assert my_cfg["ssl_ca"] == "/path/to/my_ca.pem"
        assert my_cfg["ssl_cert"] == "/path/to/my_cert.pem"
        assert my_cfg["ssl_key"] == "/path/to/my_key.pem"

        pg_cfg = cfg.config["database"]["postgresql"]
        assert pg_cfg["ssl_mode"] == "verify_ca"
        assert pg_cfg["ssl_ca"] == "/path/to/pg_ca.pem"
        assert pg_cfg["ssl_cert"] == "/path/to/pg_cert.pem"
        assert pg_cfg["ssl_key"] == "/path/to/pg_key.pem"

    def test_cli_options_merging(self):
        cfg = Config()
        cli_ns = SimpleNamespace(
            command=None,
            version_option=None,
            exc_full_stack=None,
            verbose=None,
            log_prefix=None,
            use_color=None,
            use_string_handler=None,
            dbtype=None,
            myhost=None,
            myport=None,
            mydatabase=None,
            myuser=None,
            mypassword=None,
            mypool_size=None,
            myecho=None,
            myssl_mode="verify-full",
            myssl_ca="certsd/ca_cert.pem",
            myssl_cert="certsd/client_cert.pem",
            myssl_key="certsd/client_key.pem",
            dbfile=None,
            pghost=None,
            pgport=None,
            pgdatabase=None,
            pguser=None,
            pgpassword=None,
            pgpool_size=None,
            pgecho=None,
            pgssl_mode="verify-ca",
            pgssl_ca="certsd/pg_ca.pem",
            pgssl_cert="certsd/pg_client.pem",
            pgssl_key="certsd/pg_key.pem",
            trace_sql=None,
        )
        cfg.merge_cli_options(cli_ns)

        my_cfg = cfg.config["database"]["mysql"]
        assert my_cfg["ssl_mode"] == "verify-full"
        assert my_cfg["ssl_ca"] == "certsd/ca_cert.pem"
        assert my_cfg["ssl_cert"] == "certsd/client_cert.pem"
        assert my_cfg["ssl_key"] == "certsd/client_key.pem"

        pg_cfg = cfg.config["database"]["postgresql"]
        assert pg_cfg["ssl_mode"] == "verify-ca"
        assert pg_cfg["ssl_ca"] == "certsd/pg_ca.pem"
        assert pg_cfg["ssl_cert"] == "certsd/pg_client.pem"
        assert pg_cfg["ssl_key"] == "certsd/pg_key.pem"


# Live tests against real servers when configured
MYSQL_ENV_PRESENT = all(
    os.environ.get(k)
    for k in ("OTA_TEST_MYSQL_HOST", "OTA_TEST_MYSQL_DB", "OTA_TEST_MYSQL_USER", "OTA_TEST_MYSQL_PASSWORD")
)
PG_ENV_PRESENT = all(
    os.environ.get(k)
    for k in ("OTA_TEST_PG_HOST", "OTA_TEST_PG_DB", "OTA_TEST_PG_USER", "OTA_TEST_PG_PASSWORD")
)
CERTS_PRESENT = Path(CA_CERT_PATH).is_file()


@pytest.mark.skipif(not (MYSQL_ENV_PRESENT and CERTS_PRESENT), reason="MySQL or certsd not available")
class TestMySQLLiveSSL:
    def test_mysql_live_connection_verify_full(self):
        import mysql.connector

        ssl_kwargs = get_mysql_ssl_kwargs({
            "ssl_mode": "verify_full",
            "ssl_ca": CA_CERT_PATH,
        })
        conn = mysql.connector.connect(
            host=os.environ["OTA_TEST_MYSQL_HOST"],
            port=int(os.environ.get("OTA_TEST_MYSQL_PORT", 3306)),
            database=os.environ["OTA_TEST_MYSQL_DB"],
            user=os.environ["OTA_TEST_MYSQL_USER"],
            password=os.environ["OTA_TEST_MYSQL_PASSWORD"],
            **ssl_kwargs,
        )
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW STATUS LIKE %s", ("Ssl_cipher",))
            row = cursor.fetchone()
            assert row is not None
            assert row[1] != ""  # Cipher must be non-empty (SSL in use)
        finally:
            conn.close()

    def test_mysql_live_service_pool_verify_full(self):
        from ota_http_server.database.db_mysql_service import DatabaseMySQLService

        cfg = SimpleNamespace(config={
            "parameters": {"trace_sql": False},
            "database": {
                "mysql": {
                    "myhost": os.environ["OTA_TEST_MYSQL_HOST"],
                    "myport": int(os.environ.get("OTA_TEST_MYSQL_PORT", 3306)),
                    "mydatabase": os.environ["OTA_TEST_MYSQL_DB"],
                    "myuser": os.environ["OTA_TEST_MYSQL_USER"],
                    "mypassword": os.environ["OTA_TEST_MYSQL_PASSWORD"],
                    "mypool_size": 2,
                    "myecho": False,
                    "ssl_mode": "verify_full",
                    "ssl_ca": CA_CERT_PATH,
                    "migrations_dir": "unused",
                }
            },
        })
        service = DatabaseMySQLService(cfg)
        conn = service._connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
            row = cursor.fetchone()
            assert row is not None
            assert row[1] != ""
        finally:
            conn.close()

    def test_mysql_live_migration_runner_connect_verify_full(self):
        from ota_http_server.database.migration_mysql_runner import MigrationMySQLRunner

        cfg = SimpleNamespace(config={
            "parameters": {"trace_sql": False},
            "database": {
                "mysql": {
                    "myhost": os.environ["OTA_TEST_MYSQL_HOST"],
                    "myport": int(os.environ.get("OTA_TEST_MYSQL_PORT", 3306)),
                    "mydatabase": os.environ["OTA_TEST_MYSQL_DB"],
                    "myuser": os.environ["OTA_TEST_MYSQL_USER"],
                    "mypassword": os.environ["OTA_TEST_MYSQL_PASSWORD"],
                    "mypool_size": 2,
                    "myecho": False,
                    "ssl_mode": "verify_full",
                    "ssl_ca": CA_CERT_PATH,
                    "migrations_dir": "unused",
                }
            },
        })
        runner = MigrationMySQLRunner(cfg)
        conn = runner._connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
            row = cursor.fetchone()
            assert row is not None
            assert row[1] != ""
        finally:
            conn.close()

    def test_mysql_live_connection_with_client_cert(self):
        import mysql.connector

        if not (Path(CLIENT_CERT_PATH).is_file() and Path(CLIENT_KEY_PATH).is_file()):
            pytest.skip("Client certificates not found")

        ssl_kwargs = get_mysql_ssl_kwargs({
            "ssl_mode": "verify_full",
            "ssl_ca": CA_CERT_PATH,
            "ssl_cert": CLIENT_CERT_PATH,
            "ssl_key": CLIENT_KEY_PATH,
        })
        conn = mysql.connector.connect(
            host=os.environ["OTA_TEST_MYSQL_HOST"],
            port=int(os.environ.get("OTA_TEST_MYSQL_PORT", 3306)),
            database=os.environ["OTA_TEST_MYSQL_DB"],
            user=os.environ["OTA_TEST_MYSQL_USER"],
            password=os.environ["OTA_TEST_MYSQL_PASSWORD"],
            **ssl_kwargs,
        )
        try:
            cursor = conn.cursor()
            cursor.execute("SHOW STATUS LIKE %s", ("Ssl_cipher",))
            row = cursor.fetchone()
            assert row is not None
            assert row[1] != ""
        finally:
            conn.close()


@pytest.mark.skipif(not (PG_ENV_PRESENT and CERTS_PRESENT), reason="PostgreSQL or certsd not available")
class TestPostgreSQLLiveSSL:
    def test_postgres_live_connection_verify_full(self):
        import psycopg

        ssl_kwargs = get_postgres_ssl_kwargs({
            "ssl_mode": "verify_full",
            "ssl_ca": CA_CERT_PATH,
        })
        with psycopg.connect(
            host=os.environ["OTA_TEST_PG_HOST"],
            port=int(os.environ.get("OTA_TEST_PG_PORT", 5432)),
            dbname=os.environ["OTA_TEST_PG_DB"],
            user=os.environ["OTA_TEST_PG_USER"],
            password=os.environ["OTA_TEST_PG_PASSWORD"],
            **ssl_kwargs,
        ) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            row = cursor.fetchone()
            assert row is not None
            assert row[0] is True  # ssl is True

    def test_postgres_live_service_pool_verify_full(self):
        from ota_http_server.database.db_postgres_service import DatabasePostgreSQLService

        cfg = SimpleNamespace(config={
            "parameters": {"trace_sql": False},
            "database": {
                "postgresql": {
                    "pghost": os.environ["OTA_TEST_PG_HOST"],
                    "pgport": int(os.environ.get("OTA_TEST_PG_PORT", 5432)),
                    "pgdatabase": os.environ["OTA_TEST_PG_DB"],
                    "pguser": os.environ["OTA_TEST_PG_USER"],
                    "pgpassword": os.environ["OTA_TEST_PG_PASSWORD"],
                    "pgpool_size": 2,
                    "pgecho": False,
                    "ssl_mode": "verify_full",
                    "ssl_ca": CA_CERT_PATH,
                    "migrations_dir": "unused",
                }
            },
        })
        service = DatabasePostgreSQLService(cfg)
        with service._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            row = cursor.fetchone()
            assert row is not None
            assert row[0] is True

    def test_postgres_live_migration_runner_connect_verify_full(self):
        from ota_http_server.database.migration_postgres_runner import MigrationPostgreSQLRunner

        cfg = SimpleNamespace(config={
            "parameters": {"trace_sql": False},
            "database": {
                "postgresql": {
                    "pghost": os.environ["OTA_TEST_PG_HOST"],
                    "pgport": int(os.environ.get("OTA_TEST_PG_PORT", 5432)),
                    "pgdatabase": os.environ["OTA_TEST_PG_DB"],
                    "pguser": os.environ["OTA_TEST_PG_USER"],
                    "pgpassword": os.environ["OTA_TEST_PG_PASSWORD"],
                    "pgpool_size": 2,
                    "pgecho": False,
                    "ssl_mode": "verify_full",
                    "ssl_ca": CA_CERT_PATH,
                    "migrations_dir": "unused",
                }
            },
        })
        runner = MigrationPostgreSQLRunner(cfg)
        conn = runner._connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            row = cursor.fetchone()
            assert row is not None
            assert row[0] is True
        finally:
            conn.close()

    def test_postgres_live_connection_with_client_cert(self):
        import psycopg

        if not (Path(CLIENT_CERT_PATH).is_file() and Path(CLIENT_KEY_PATH).is_file()):
            pytest.skip("Client certificates not found")

        ssl_kwargs = get_postgres_ssl_kwargs({
            "ssl_mode": "verify_full",
            "ssl_ca": CA_CERT_PATH,
            "ssl_cert": CLIENT_CERT_PATH,
            "ssl_key": CLIENT_KEY_PATH,
        })
        with psycopg.connect(
            host=os.environ["OTA_TEST_PG_HOST"],
            port=int(os.environ.get("OTA_TEST_PG_PORT", 5432)),
            dbname=os.environ["OTA_TEST_PG_DB"],
            user=os.environ["OTA_TEST_PG_USER"],
            password=os.environ["OTA_TEST_PG_PASSWORD"],
            **ssl_kwargs,
        ) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            row = cursor.fetchone()
            assert row is not None
            assert row[0] is True
