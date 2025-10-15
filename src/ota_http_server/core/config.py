# core/config.py

import sys
import os
from typing import Dict, Any
import argparse
from jsonschema import validate, ValidationError

from ota_http_server.logger import get_app_logger

logger = get_app_logger(__name__)

# Check Python version at runtime
if sys.version_info >= (3, 11):
    import tomllib as toml # Use the built-in tomllib for Python 3.11+
else:
    import tomli as toml # Use the external tomli for Python 3.7 to 3.10

class Config:
    def __init__(self) -> None:
        self.config = self.DEFAULT_CONFIG

    DEFAULT_CONFIG = {
        'template': {
            'template_name': "pymodule",
            'template_version': "3.1.3",
            'template_description': { 'text': """Template with CLI interface, configuration options in a file, logger and unit tests""", 'content-type': "text/plain" }
        },
        'metadata': {
            'version': False
        },
        'logging': {
            'verbose': False
        },
        'parameters': {
            'cert': "cert.pem",
            'key': "key.pem",
            'no-certs': False,
            'no-jwt': False,
            'jwt-alg': None,
            'jwt-expiry': 12,
            'jwt-secret': None,
            'admin-secret': None,
            'host': "0.0.0.0",
            'port': 8071,
            'www-dir': "www",
            'firmware-dir': "firmware",
            'url-firmware': "firmware",
            'ota-audit-log': "ota_audit_log.csv"
        }
    }

    # When adding / removing changing configuration parameters, change following validation appropriately
    CONFIG_SCHEMA = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "metadata": {
                "type": "object",
                "properties": {
                    "version": {
                        "type": "boolean"
                    }
                },
                "additionalProperties": False
            },
            "logging": {
                "type": "object",
                "properties": {
                    "verbose": {
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
                    "no-certs": {
                        "type": "boolean"
                    },
                    "no-jwt": {
                        "type": "boolean"
                    },
                    "jwt-alg": {
                        "type": "string"
                    },
                    "jwt-expiry": {
                        "type": "number"
                    },
                    "jwt-secret": {
                        "type": ["string", "null"]
                    },
                    "admin-secret": {
                        "type": ["string", "null"]
                    },
                    "host": {
                        "type": "string"
                    },
                    "port": {
                        "type": "number"
                    },
                    "www-dir": {
                        "type": "string"
                    },
                    "firmware-dir": {
                        "type": "string"
                    },
                    "url-firmware": {
                        "type": "string"
                    },
                    "ota-audit-log": {
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

    def deep_update(self,config: Dict[str, Any], config_file: Dict[str, Any]) -> None:
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
                # Otherwise, update the key with the new value from config_file
                config[key] = value

    def load_config_env(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables.

        :return: Updated configuration dictionary
        """
        env_overrides = {
            "parameters": {
                "jwt-alg": os.getenv("OTA_JWT_ALGORITHM"),
                "jwt-expiry": os.getenv("OTA_JWT_EXPIRY_MINUTES"),
                "jwt-secret": os.getenv("OTA_JWT_SECRET"),
                "admin-secret": os.getenv("OTA_ADMIN_SECRET"),
                "ota-audit-log": os.getenv("OTA_AUDIT_LOG")
            }
        }
        self.deep_update(config=self.config, config_file=env_overrides)

        return self.config

    def merge_options(self, config_cli: argparse.Namespace | None = None) -> Dict[str, Any]:
        # handle CLI options if started from CLI interface
        if config_cli:

            if config_cli.app_version is not None:
                self.config['metadata']['version'] = config_cli.app_version
            # Handle general options
            if config_cli.verbose is not None:
                self.config['logging']['verbose'] = config_cli.verbose

            # sample parameters that should be changed in real applications
            if config_cli.cert is not None:
                self.config['parameters']['cert'] = config_cli.cert
            if config_cli.key is not None:
                self.config['parameters']['key'] = config_cli.key
            if config_cli.no_certs is not None:
                self.config['parameters']['no-certs'] = config_cli.no_certs
            if config_cli.no_jwt is not None:
                self.config['parameters']['no-jwt'] = config_cli.no_jwt
            if config_cli.jwt_alg is not None:
                self.config['parameters']['jwt-alg'] = config_cli.jwt_alg
            if config_cli.jwt_expiry is not None:
                self.config['parameters']['jwt-expiry'] = config_cli.jwt_expiry
            if config_cli.jwt_secret is not None:
                self.config['parameters']['jwt-secret'] = config_cli.jwt_secret
            if config_cli.admin_secret is not None:
                self.config['parameters']['admin-secret'] = config_cli.admin_secret
            # server parameters
            if config_cli.host is not None:
                self.config['parameters']['host'] = config_cli.host
            if config_cli.port is not None:
                self.config['parameters']['port'] = config_cli.port
            if config_cli.www_dir is not None:
                self.config['parameters']['www-dir'] = config_cli.www_dir
            if config_cli.firmware_dir is not None:
                self.config['parameters']['firmware-dir'] = config_cli.firmware_dir
            if config_cli.url_firmware is not None:
                self.config['parameters']['url-firmware'] = config_cli.url_firmware
            # logging parameters
            if config_cli.ota_audit_log is not None:
                self.config['parameters']['ota-audit-log'] = config_cli.ota_audit_log

        return self.config
