# core/config.py

import os
import sys
from typing import Dict, Any, Mapping, TypedDict
import argparse
from jsonschema import validate, ValidationError

from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

# Check Python version at runtime
if sys.version_info >= (3, 11):
    import tomllib as toml # Use the built-in tomllib for Python 3.11+
else:
    import tomli as toml # Use the external tomli for Python 3.7 to 3.10

class TemplateConfig(TypedDict, total=False):
    template_name: str
    template_version: str
    template_description: Dict[str, Any]

class LoggingConfig(TypedDict, total=False):
    verbose: int
    log_prefix: bool
    use_color: bool
    use_string_handler: bool
    version_option: bool

class ParametersConfig(TypedDict, total=False):
    cert: str
    key: str
    no_certs: bool
    no_jwt: bool
    jwt_alg: str
    jwt_expiry: int
    jwt_max_expiry: int
    jwt_secret: str | None
    jwt_issuer: str | None
    jwt_audience: str | None
    admin_secret: str | None
    host: str
    port: int
    www_dir: str
    firmware_dir: str
    url_firmware: str
    ota_audit_log: str
    ota_db: str
    ota_db_cache_ttl: int

class DatabaseConfig(TypedDict, total=False):
    dbhost: str
    dbport: int
    database: str
    dbuser: str
    dbpassword: str
    dbpool_size: int
    dbecho: bool

class ConfigDict(TypedDict):
    template: TemplateConfig
    logging: LoggingConfig
    parameters: ParametersConfig
    database: DatabaseConfig

class Config:
    def __init__(self) -> None:
        self.config: ConfigDict = self.DEFAULT_CONFIG

    DEFAULT_CONFIG: ConfigDict = {
        'template': {
            'template_name': "pymodule",
            'template_version': "4.0.2",
            'template_description': { 'text': """Template with CLI interface, configuration options in a file, logger and unit tests""", 'content-type': "text/plain" }
        },
        'logging': {
            'verbose': 3,
            'log_prefix': True,
            'use_color': True,
            'use_string_handler': False,
            'version_option': False
        },
        'parameters': {
            'cert': "cert.pem",
            'key': "key.pem",
            'no_certs': False,
            'no_jwt': False,
            'jwt_alg': "HS256",
            'jwt_expiry': 300,
            'jwt_max_expiry': 3600,
            'jwt_secret': None,
            'jwt_issuer': "ota_http_server",
            'jwt_audience': "ota_api",
            'admin_secret': None,
            'host': "0.0.0.0",
            'port': 8071,
            'www_dir': "www",
            'firmware_dir': "firmware",
            'url_firmware': "firmware",
            'ota_audit_log': "ota_audit_log.csv",
            'ota_db': "ota_db.toml",
            'ota_db_cache_ttl': 300
        },
        'database': {
            'dbhost': "localhost",
            'dbport': 3306,
            'database': "ota_db",
            'dbuser': "ota_user",
            'dbpassword': "ota_password",
            'dbpool_size': 10,
            'dbecho': False
        }
    }

    # When adding / removing changing configuration parameters, change following validation appropriately
    CONFIG_SCHEMA = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "logging": {
                "type": "object",
                "properties": {
                    "verbose": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 6
                    },
                    "log_prefix": {
                        "type": "boolean"
                    },
                    "use_color": {
                        "type": "boolean"
                    },
                    "use_string_handler": {
                        "type": "boolean"
                    },
                    "version_option": {
                        "type": "boolean"
                    }
                },
                "additionalProperties": False
            },
            "parameters": {
                "type": "object",
                "properties": {
                    "cert": {
                        "type": "string"
                    },
                    "key": {
                        "type": "string"
                    },
                    "no_certs": {
                        "type": "boolean"
                    },
                    "no_jwt": {
                        "type": "boolean"
                    },
                    "jwt_alg": {
                        "type": "string"
                    },
                    "jwt_expiry": {
                        "type": "number"
                    },
                    "jwt_max_expiry": {
                        "type": "number"
                    },
                    "jwt_secret": {
                        "type": ["string", "null"]
                    },
                    "jwt_issuer": {
                        "type": ["string", "null"]
                    },
                    "jwt_audience": {
                        "type": ["string", "null"]
                    },
                    "admin_secret": {
                        "type": ["string", "null"]
                    },
                    "host": {
                        "type": "string"
                    },
                    "port": {
                        "type": "number"
                    },
                    "www_dir": {
                        "type": "string"
                    },
                    "firmware_dir": {
                        "type": "string"
                    },
                    "url_firmware": {
                        "type": "string"
                    },
                    "ota_audit_log": {
                        "type": "string"
                    },
                    "ota_db": {
                        "type": "string"
                    },
                    "ota_db_cache_ttl": {
                        "type": "number"
                    }
                },
                "additionalProperties": False
            },
            "database": {
                "type": "object",
                "properties": {
                    "dbhost": {
                        "type": "string"
                    },
                    "dbport": {
                        "type": "number"
                    },
                    "database": {
                        "type": "string"
                    },
                    "dbuser": {
                        "type": "string"
                    },
                    "dbpassword": {
                        "type": "string"
                    },
                    "dbpool_size": {
                        "type": "number"
                    },
                    "dbecho": {
                        "type": "boolean"
                    }
                },
                 "additionalProperties": False
            }
        },
        "additionalProperties": False
    }

    def load_toml(self,file_path:str) -> Dict[str, Any]:
        """
        Load a TOML file with exception handling.

        :param file_path: Path to the TOML file
        :return: Parsed TOML data as a dictionary
        :raises FileNotFoundError: If the file does not exist
        :raises tomli.TOMLDecodeError / tomllib.TOMLDecodeError: If there is a parsing error
        """
        try:
            # Open the file in binary mode (required by both tomli and tomllib)
            with open(file_path, 'rb') as f:
                return toml.load(f)

        except FileNotFoundError as e:
            logger.error("%s",str(e))
            raise e  # Optionally re-raise the exception if you want to propagate it
        except toml.TOMLDecodeError as e:
            logger.error("Error: Failed to parse TOML file '%s'. Invalid TOML syntax.",file_path)
            raise e  # Re-raise the exception for further handling
        except Exception as e:
            logger.error("An unexpected error occurred while loading the TOML file: %s",str(e))
            raise e  # Catch-all for any other unexpected exceptions

    def load_config_file(self, file_path: str="config.toml") -> Dict[str, Any]:
        # skip the configuration file if an empty name is given
        if file_path == '':
            return {}
        # Convert None to default value of 'config.json'
        if file_path == "config.toml":
            logger.warning("CFG: Using default '%s'",file_path)
            file_path = 'config.toml'
        try:
            config_file = self.load_toml(file_path=file_path)
            validate(instance=config_file, schema=self.CONFIG_SCHEMA)
        except ValidationError as e:
            logger.warning("Configuration validation error in %s: %s",file_path,str(e))
            raise ValueError from e
        except Exception as e:
            logger.error("Exception when trying to load %s: %s",file_path,str(e))
            raise e

        self.deep_update(config=self.config, config_file=config_file)

        return config_file

    def deep_update(self,config:Mapping[str, Any], config_file: Dict[str, Any]) -> None:
        """
        Recursively updates a dictionary (`config`) with the contents of another dictionary (`config_file`).
        It performs a deep merge, meaning that if a key contains a nested dictionary in both `config`
        and `config_file`, the nested dictionaries are merged instead of replaced.

        Parameters:
        - config (Dict[str, Any]): The original dictionary to be updated.
        - config_file (Dict[str, Any]): The dictionary containing updated values.

        Returns:
        - None: The update is done in place, so the `config` dictionary is modified directly.
        """
        for key, value in config_file.items():
            if isinstance(value, dict) and key in config and isinstance(config[key], dict):
                # If both values are dictionaries, recurse to merge deeply
                self.deep_update(config[key], value)
            else:
                # Otherwise, update the key with the new value from config_file if it is present there
                if value is not None:
                    config[key] = value

    def load_config_env(self) -> ConfigDict:
        """
        Load configuration from environment variables.

        :return: Updated configuration dictionary
        """
        env_overrides = {
            "parameters": {
                "jwt_alg": os.getenv("OTA_JWT_ALGORITHM"),
                "jwt_expiry": os.getenv("OTA_JWT_EXPIRY_SECONDS"),
                "jwt_max_expiry": os.getenv("OTA_JWT_MAX_EXPIRY_SECONDS"),
                "jwt_secret": os.getenv("OTA_JWT_SECRET"),
                "admin_secret": os.getenv("OTA_ADMIN_SECRET"),
                "ota_audit_log": os.getenv("OTA_AUDIT_LOG"),
                "jwt_issuer": os.getenv("OTA_JWT_ISSUER"),
                "jwt_audience": os.getenv("OTA_JWT_AUDIENCE"),
                "ota_db": os.getenv("OTA_DATABASE"),
                "ota_db_cache_ttl": os.getenv("OTA_DB_CACHE_TTL")
            },
            "database": {
                "dbhost": os.getenv("OTA_DB_HOST"),
                "dbport": os.getenv("OTA_DB_PORT"),
                "database": os.getenv("OTA_DB"),
                "dbuser": os.getenv("OTA_DB_USER"),
                "dbpassword": os.getenv("OTA_DB_PASSWORD"),
                "dbpool_size": os.getenv("OTA_DB_POOL_SIZE"),
                "dbecho": os.getenv("OTA_DB_ECHO")
             }
        }
        self.deep_update(config=self.config, config_file=env_overrides)

        return self.config

    def merge_cli_options(self, config_cli: argparse.Namespace | None = None) -> ConfigDict:    # pylint: disable=too-many-branches
        # handle CLI options if started from CLI interface
        if config_cli:
            if config_cli.command is not None:
                self.config['command'] = config_cli.command

            if config_cli.version_option is not None:
                self.config['logging']['version_option'] = config_cli.version_option

            # Handle general options
            if config_cli.verbose is not None:
                self.config['logging']['verbose'] = config_cli.verbose
            if config_cli.log_prefix is not None:
                self.config['logging']['log_prefix'] = config_cli.log_prefix
            if config_cli.use_color is not None:
                self.config['logging']['use_color'] = config_cli.use_color
            if config_cli.use_string_handler is not None:
                self.config['logging']['use_string_handler'] = config_cli.use_string_handler

            # handle database options
            if config_cli.dbhost is not None:
                self.config['database']['dbhost'] = config_cli.dbhost
            if config_cli.dbport is not None:
                self.config['database']['dbport'] = config_cli.dbport
            if config_cli.database is not None:
                self.config['database']['database'] = config_cli.database
            if config_cli.dbuser is not None:
                self.config['database']['dbuser'] = config_cli.dbuser
            if config_cli.dbpassword is not None:
                self.config['database']['dbpassword'] = config_cli.dbpassword
            if config_cli.dbpool_size is not None:
                self.config['database']['dbpool_size'] = config_cli.dbpool_size
            if config_cli.dbecho is not None:
                self.config['database']['dbecho'] = config_cli.dbecho

            if config_cli.command == 'runserver':
                if config_cli.cert is not None:
                    self.config['parameters']['cert'] = config_cli.cert
                if config_cli.key is not None:
                    self.config['parameters']['key'] = config_cli.key
                if config_cli.no_certs is not None:
                    self.config['parameters']['no_certs'] = config_cli.no_certs
                if config_cli.no_jwt is not None:
                    self.config['parameters']['no_jwt'] = config_cli.no_jwt
                if config_cli.jwt_alg is not None:
                    self.config['parameters']['jwt_alg'] = config_cli.jwt_alg
                if config_cli.jwt_expiry is not None:
                    self.config['parameters']['jwt_expiry'] = config_cli.jwt_expiry
                if config_cli.jwt_max_expiry is not None:
                    self.config['parameters']['jwt_max_expiry'] = config_cli.jwt_max_expiry
                if config_cli.jwt_secret is not None:
                    self.config['parameters']['jwt_secret'] = config_cli.jwt_secret
                if config_cli.jwt_issuer is not None:
                    self.config['parameters']['jwt_issuer'] = config_cli.jwt_issuer
                if config_cli.jwt_audience is not None:
                    self.config['parameters']['jwt_audience'] = config_cli.jwt_audience
                if config_cli.admin_secret is not None:
                    self.config['parameters']['admin_secret'] = config_cli.admin_secret
                if config_cli.ota_db is not None:
                    self.config["parameters"]["ota_db"] = config_cli.ota_db
                if config_cli.ota_db_cache_ttl is not None:
                    self.config["parameters"]["ota_db_cache_ttl"] = config_cli.ota_db_cache_ttl
                # server parameters
                if config_cli.host is not None:
                    self.config['parameters']['host'] = config_cli.host
                if config_cli.port is not None:
                    self.config['parameters']['port'] = config_cli.port
                if config_cli.www_dir is not None:
                    self.config['parameters']['www_dir'] = config_cli.www_dir
                if config_cli.firmware_dir is not None:
                    self.config['parameters']['firmware_dir'] = config_cli.firmware_dir
                if config_cli.url_firmware is not None:
                    self.config['parameters']['url_firmware'] = config_cli.url_firmware
                # logging parameters
                if config_cli.ota_audit_log is not None:
                    self.config['parameters']['ota_audit_log'] = config_cli.ota_audit_log

            if config_cli.command == 'db':
                if config_cli.db_command is not None:
                    self.config['db_command'] = config_cli.db_command
                # here db commands must be handled for parameters
        return self.config

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments, including nested options for mqtt and MS Protocol."""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Secure OTA server with JWT and audit logging',
                                     epilog="""
Configuration priority: (lowest) defaults -> config file -> environment variables -> CLI options (highest)

Examples:

options:
  -h, --help     show this help message and exit

Environment variables:
  OTA_JWT_ALGORITHM       JWT algorithm to use (default 'HS256')
  OTA_JWT_EXPIRY_SECONDS  JWT expiry time in seconds (default 300)
  OTA_JWT_MAX_EXPIRY_SECONDS JWT max expiry time in seconds (default 3600)
  OTA_JWT_SECRET          JWT secret key, can be overridden by --jwt-secret CLI option
  OTA_ADMIN_SECRET        Admin secret key, can be overridden by --admin-secret CLI option
  OTA_JWT_ISSUER          JWT issuer claim value, can be overridden by --jwt-issuer CLI option
  OTA_JWT_AUDIENCE        JWT audience claim value, can be overridden by --jwt-audience CLI option
  OTA_AUDIT_LOG           Path to the OTA audit log file (default 'ota_audit_log.csv'), can be overridden by --ota-audit-log CLI option
  OTA_DB                  Path to the OTA database file (default 'ota_db.toml'), can be overridden by --ota-db CLI option
  OTA_DB_CACHE_TTL        Cache time-to-live for the OTA database in seconds (default 300), can be overridden by --ota-db-cache-ttl CLI option
  OTA_DB_HOST             Database host (default 'localhost'), can be overridden by --dbhost CLI option
  OTA_DB_PORT             Database port (default 3306), can be overridden by --dbport CLI option
  OTA_DATABASE            Database name (default 'ota_db'), can be overridden by --ota-db CLI option
  OTA_DB_USER             Database user (default 'ota_user'), can be overridden by --dbuser CLI option
  OTA_DB_PASSWORD         Database password, can be overridden by --dbpassword CLI option
  OTA_DB_POOL_SIZE        Database connection pool size (default 10), can be overridden by --dbpool-size CLI option
  OTA_DB_ECHO             Enable database echo (default False), can be overridden by --dbecho CLI option

Examples:

Use default configuration values in the program, default config file is 'config.toml' in the current directory and environment variables:
  ota_http_server

Use a different port than the default 8071:
  ota_http_server --port 18070

Use a custom configuration file instead of the default 'config.toml':
  ota_http_server --config myota/config.toml

For use behind a reverse proxy with SSL termination, you can disable certificates in the OTA server and let the reverse proxy handle SSL:
  ota_http_server --no-certs

For use in development when no JWT authentication is needed, you can disable JWT:
  ota_http_server --no-jwt

For use in development environment without SSL certificates and JWT authentication, you can disable both:
  ota_http_server --no-certs --no-jwt
"""
)

    # -------------------
    # General options
    # -------------------
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument(
        '--config',
        type=str,
        dest='config',
        default='config.toml',
        help="Name of the configuration file, default is 'config.toml'"
    )
    general_group.add_argument(
        '--no-config',
        action='store_const',
        const='',
        dest='config',
        help="Do not use a configuration file (only defaults & options)"
    )
    general_group.add_argument(
        '-v',
        dest='version_option',
        action='store_true',
        default=False,
        help='Show version information of the module'
    )

    # -------------------
    # Logging options
    # -------------------
    logging_group = parser.add_argument_group("Logging Options")
    logging_group.add_argument(
        '--verbose',
        type=int,
        choices=[0, 1, 2, 3, 4, 5, 6],
        dest='verbose',
        help="Verbosity level: 0=CRITICAL, 1=ERROR, 2=WARNING, 3=QUIET, 4=INFO, 5=VERBOSE, 6=DEBUG. Default hardcoded is 3 or taken from config file/environment variable."
    )
    prefix_group = logging_group.add_mutually_exclusive_group()
    prefix_group.add_argument(
        "--log-prefix",
        action="store_const",
        const=True,
        dest="log_prefix",
        help="Enable log prefixes (timestamp, module, level)"
    )
    prefix_group.add_argument(
        "--no-log-prefix",
        action="store_const",
        const=False,
        dest="log_prefix",
        help="Disable log prefixes (print only the message)"
    )
    color_group = logging_group.add_mutually_exclusive_group()
    color_group.add_argument(
        "--use-color",
        action="store_const",
        const=True,
        dest="use_color",
        help="Enable colored log output"
    )
    color_group.add_argument(
        "--no-use-color",
        action="store_const",
        const=False,
        dest="use_color",
        help="Disable colored log output"
    )
    string_handler_group = logging_group.add_mutually_exclusive_group()
    string_handler_group.add_argument(
        "--use-string-handler",
        action="store_const",
        const=True,
        dest="use_string_handler",
        help="Enable string handler to store logs in an internal buffer"
    )
    string_handler_group.add_argument(
        "--no-use-string-handler",
        action="store_const",
        const=False,
        dest="use_string_handler",
        help="Disable string handler to store logs in an internal buffer"
    )

    # database options
    db_group = parser.add_argument_group("Database")
    db_group.add_argument("--dbhost", dest="dbhost", type=str, help="Database host (default 'localhost'), overrides OTA_DB_HOST environment variable")
    db_group.add_argument("--dbport", dest="dbport", type=int, help="Database port (default 3306), overrides OTA_DB_PORT environment variable")
    db_group.add_argument("--database", dest="database", type=str, help="Database name (default 'ota_db'), overrides OTA_DATABASE environment variable")
    db_group.add_argument("--dbuser", dest="dbuser", type=str, help="Database user (default 'ota_user'), overrides OTA_DB_USER environment variable")
    db_group.add_argument("--dbpassword", dest="dbpassword", type=str, help="Database password, overrides OTA_DB_PASSWORD environment variable")
    db_group.add_argument("--dbpool-size", dest="dbpool_size", type=int, help="Database connection pool size (default 10), overrides OTA_DB_POOL_SIZE environment variable")
    dbecho_group = db_group.add_mutually_exclusive_group()
    dbecho_group.add_argument("--dbecho", dest="dbecho", action="store_const", const=True, help="Enable database echo (default False), overrides OTA_DB_ECHO environment variable")
    dbecho_group.add_argument("--no-dbecho", dest="dbecho", action="store_const", const=False, help="Disable database echo (default False), overrides OTA_DB_ECHO environment variable")

    # application options & parameters
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("runserver", help="Start OTA HTTP server")

    certs_group = run_parser.add_argument_group("Certificates")
    certs_ex_group = certs_group.add_mutually_exclusive_group()
    certs_ex_group.add_argument("--no-certs", dest="no_certs", action="store_const", const=True, help="Disable SSL certificates (use plain HTTP)")
    certs_ex_group.add_argument("--certs", dest="no_certs", action="store_const", const=False, help="Enable SSL certificates (use plain HTTP)")
    certs_group.add_argument("--cert", dest="cert", help="Path to certificate file")
    certs_group.add_argument("--key", dest="key", help="Path to private key file")

    jwt_group = run_parser.add_argument_group("JWT")
    jwt_ex_group = jwt_group.add_mutually_exclusive_group()
    jwt_ex_group.add_argument("--no-jwt", dest="no_jwt", action="store_const", const=True, help="Disable JWT authentication (not recommended)")
    jwt_ex_group.add_argument("--jwt", dest="no_jwt", action="store_const", const=False, help="Enable JWT authentication")
    jwt_group.add_argument("--jwt-alg", dest="jwt_alg", type=str, help="JWT algorithm to use (default 'HS256'), overrides OTA_JWT_ALGORITHM environment variable")
    jwt_group.add_argument("--jwt-expiry", dest="jwt_expiry", type=int, help="JWT expiry time in seconds (default 300), overrides OTA_JWT_EXPIRY_SECONDS environment variable")
    jwt_group.add_argument("--jwt-max-expiry", dest="jwt_max_expiry", type=int, help="JWT max expiry time in seconds (default 3600), overrides OTA_JWT_MAX_EXPIRY_SECONDS environment variable")
    jwt_group.add_argument("--jwt-secret", dest="jwt_secret", type=str, help="JWT secret key, overrides OTA_JWT_SECRET environment variable")
    jwt_group.add_argument("--jwt-issuer", dest="jwt_issuer", type=str, help="JWT issuer claim value, overrides OTA_JWT_ISSUER environment variable")
    jwt_group.add_argument("--jwt-audience", dest="jwt_audience", type=str, help="JWT audience claim value, overrides OTA_JWT_AUDIENCE environment variable")
    jwt_group.add_argument("--admin-secret", dest="admin_secret", type=str, help="Admin secret key, overrides OTA_ADMIN_SECRET environment variable")

    db_group = run_parser.add_argument_group("TOML Database")
    db_group.add_argument("--ota-db", dest="ota_db", type=str, help="Path to the OTA database file (default 'ota_db.toml'), overrides OTA_DB environment variable")
    db_group.add_argument("--ota-db-cache-ttl", dest="ota_db_cache_ttl", type=int, help="Cache time-to-live for the OTA database in seconds (default 300), overrides OTA_DB_CACHE_TTL environment variable")

    server_group = run_parser.add_argument_group("Server", description="""Server configuration options
  Firmware URL has format host:port/url_firmware/project/filename-prefix-version.bin.
  'url_firmware' is usually 'firmware' and corresponds to 'firmware-dir' in the file system under 'www-dir'.
  'www-dir' is the root directory of the http server.""")
    server_group.add_argument("--host", dest="host", help="Listening host")
    server_group.add_argument("--port", dest="port", type=int, help="Listening port")
    server_group.add_argument("--www-dir", dest="www_dir", help="Root directory for files (default 'www')")
    server_group.add_argument("--firmware-dir", dest="firmware_dir", help="Subdirectory for firmware files (default 'firmware')")
    server_group.add_argument("--url-firmware", dest="url_firmware", help="The URL path segment for firmware (default 'firmware', corresponds with `firmware-dir`)")

    logging_group = run_parser.add_argument_group("Logging")
    logging_group.add_argument("--ota-audit-log", dest="ota_audit_log", help="Path to the OTA audit log file (default 'ota_audit_log.csv'), overrides OTA_AUDIT_LOG environment variable")

#############

    db_parser = subparsers.add_parser("db", help="Database operations")
    db_subparsers = db_parser.add_subparsers(dest="db_command", required=True)

    create_user_parser = db_subparsers.add_parser("create-user", help="Create a user")
    create_user_parser.add_argument("--email", required=True)

    assign_parser = db_subparsers.add_parser("assign-device", help="Assign device to user")
    assign_parser.add_argument("--user-id", required=True)
    assign_parser.add_argument("--device-id", required=True)

    return parser.parse_args()

def get_app_configuration() -> Config:
    """Get the application configuration.

    This function initializes the Config class, loads the configuration file,
    applies environment variable overrides, and returns the final configuration.

    Returns:
        ConfigDict: The final application configuration.
    """

    # Step 1: Create config object with default configuration
    config_instance = Config()

    # Step 2: Parse command-line arguments
    args = parse_args()
    if args.version_option:
        # If version option is requested, skip loading other configurations
        config_instance.config['logging']['version_option'] = True
        return config_instance

    # Step 3: Try to load configuration from configuration file
    config_file = args.config
    try:
        config_instance.load_config_file(config_file)
    except Exception as e:
        logger.info("Error with loading configuration file. Giving up.\n%s",str(e))
        raise

    # Step 4: Load config from environment variables (if set)
    try:
        config_instance.load_config_env()
    except Exception as e:
        logger.info("Error with loading environment variables. Giving up.\n%s",str(e))
        raise

    # Step 5: Merge default config, config.json, and command-line arguments
    config_instance.merge_cli_options(args)

    return config_instance
