# core/config.py

import sys
import os
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

class MetaDataConfig(TypedDict, total=False):
    version: str

class LoggingConfig(TypedDict, total=False):
    verbose: bool
    version_option: bool

class ParametersConfig(TypedDict, total=False):
    cert: str
    key: str
    no_certs: bool
    no_jwt: bool
    jwt_alg: str
    jwt_expiry: int
    jwt_secret: str | None
    admin_secret: str | None
    host: str
    port: int
    www_dir: str
    firmware_dir: str
    url_firmware: str
    ota_audit_log: str

class ConfigDict(TypedDict):
    template: TemplateConfig
    logging: LoggingConfig
    parameters: ParametersConfig

class Config:
    def __init__(self) -> None:
        self.config: ConfigDict = self.DEFAULT_CONFIG

    DEFAULT_CONFIG: ConfigDict = {
        'template': {
            'template_name': "pymodule",
            'template_version': "3.1.3",
            'template_description': { 'text': """Template with CLI interface, configuration options in a file, logger and unit tests""", 'content-type': "text/plain" }
        },
        'logging': {
            'verbose': False,
            'version_option': False
        },
        'parameters': {
            'cert': "cert.pem",
            'key': "key.pem",
            'no_certs': False,
            'no_jwt': False,
            'jwt_alg': "HS256",
            'jwt_expiry': 12,
            'jwt_secret': None,
            'admin_secret': None,
            'host': "0.0.0.0",
            'port': 8071,
            'www_dir': "www",
            'firmware_dir': "firmware",
            'url_firmware': "firmware",
            'ota_audit_log': "ota_audit_log.csv"
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
                    "jwt_secret": {
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
                    config[key] = value     # type: ignore[index]

    def load_config_env(self) -> ConfigDict:
        """
        Load configuration from environment variables.

        :return: Updated configuration dictionary
        """
        env_overrides = {
            "parameters": {
                "jwt_alg": os.getenv("OTA_JWT_ALGORITHM"),
                "jwt_expiry": os.getenv("OTA_JWT_EXPIRY_MINUTES"),
                "jwt_secret": os.getenv("OTA_JWT_SECRET"),
                "admin_secret": os.getenv("OTA_ADMIN_SECRET"),
                "ota_audit_log": os.getenv("OTA_AUDIT_LOG")
            }
        }
        self.deep_update(config=self.config, config_file=env_overrides)

        return self.config

    def merge_cli_options(self, config_cli: argparse.Namespace | None = None) -> ConfigDict:    # pylint: disable=too-many-branches
        # handle CLI options if started from CLI interface
        if config_cli:
            if config_cli.version_option is not None:
                self.config['logging']['version_option'] = config_cli.version_option

            # Handle general options
            if config_cli.verbose is not None:
                self.config['logging']['verbose'] = config_cli.verbose

            # sample parameters that should be changed in real applications
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
            if config_cli.jwt_secret is not None:
                self.config['parameters']['jwt_secret'] = config_cli.jwt_secret
            if config_cli.admin_secret is not None:
                self.config['parameters']['admin_secret'] = config_cli.admin_secret
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

        return self.config

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments, including nested options for mqtt and MS Protocol."""
    parser = argparse.ArgumentParser(description='Secure OTA server with JWT and audit logging')

    # configuration file name
    parser.add_argument('--config', type=str, dest='config', default='config.toml',\
                        help="Name of the configuration file, default is 'config.toml'")
    parser.add_argument('--no-config', action='store_const', const='', dest='config',\
                        help="Do not use a configuration file (only defaults & options)")

    # version
    parser.add_argument('-v', dest='version_option', action='store_true', default = False, help='Show version information of the module')

    # Verbosity option
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('--verbose', dest='verbose', action='store_const',\
                                 const=True, help='Enable verbose mode')
    verbosity_group.add_argument('--no-verbose', dest='verbose', action='store_const',\
                                 const=False, help='Disable verbose mode')

    # application options & parameters

    certs_group = parser.add_argument_group("Certificates")
    certs_ex_group = certs_group.add_mutually_exclusive_group()
    certs_ex_group.add_argument("--no-certs", dest="no_certs", action="store_const", const=True, help="Disable SSL certificates (use plain HTTP)")
    certs_ex_group.add_argument("--certs", dest="no_certs", action="store_const", const=False, help="Enable SSL certificates (use plain HTTP)")
    certs_group.add_argument("--cert", dest="cert", help="Path to certificate file")
    certs_group.add_argument("--key", dest="key", help="Path to private key file")

    jwt_group = parser.add_argument_group("JWT")
    jwt_ex_group = jwt_group.add_mutually_exclusive_group()
    jwt_ex_group.add_argument("--no-jwt", dest="no_jwt", action="store_const", const=True, help="Disable JWT authentication (not recommended)")
    jwt_ex_group.add_argument("--jwt", dest="no_jwt", action="store_const", const=False, help="Enable JWT authentication")
    jwt_group.add_argument("--jwt-alg", dest="jwt_alg", type=str, help="JWT algorithm to use (default 'HS256'), overrides OTA_JWT_ALGORITHM environment variable")
    jwt_group.add_argument("--jwt-expiry", dest="jwt_expiry", type=int, help="JWT expiry time in minutes (default 30), overrides OTA_JWT_EXPIRY_MINUTES environment variable")
    jwt_group.add_argument("--jwt-secret", dest="jwt_secret", type=str, help="JWT secret key, overrides OTA_JWT_SECRET environment variable")
    jwt_group.add_argument("--admin-secret", dest="admin_secret", type=str, help="Admin secret key, overrides OTA_ADMIN_SECRET environment variable")

    server_group = parser.add_argument_group("Server")
    server_group.add_argument("--host", dest="host", help="Listening host")
    server_group.add_argument("--port", dest="port", type=int, help="Listening port")
    server_group.add_argument("--www-dir", dest="www_dir", help="Root directory for files (default 'www')")
    server_group.add_argument("--firmware-dir", dest="firmware_dir", help="Subdirectory for firmware files (default 'firmware')")
    server_group.add_argument("--url-firmware", dest="url_firmware", help="The URL path segment for firmware (default 'firmware', corresponds with `firmware-dir`)")

    logging_group = parser.add_argument_group("Logging")
    logging_group.add_argument("--ota-audit-log", dest="ota_audit_log", help="Path to the OTA audit log file (default 'ota_audit_log.csv'), overrides OTA_AUDIT_LOG environment variable")

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
