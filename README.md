# OTA Firmware Server

- [OTA Firmware Server](#ota-firmware-server)
  - [🗺 Architecture](#-architecture)
  - [🚀 Quick Start (source installation)](#-quick-start-source-installation)
    - [Prerequisites](#prerequisites)
    - [Installing `ota_http_server` as a editable project](#installing-ota_http_server-as-a-editable-project)
    - [Run the server.](#run-the-server)
  - [Features](#features)
  - [Editable project - directory Structure](#editable-project---directory-structure)
  - [Configuration](#configuration)
    - [Default Hardcoded Values (Lowest Priority).](#default-hardcoded-values-lowest-priority)
    - [Configuration File (`config.toml`)](#configuration-file-configtoml)
    - [Environment Variables.](#environment-variables)
    - [Command-Line Options (Highest Priority)](#command-line-options-highest-priority)
    - [Configuration Hierarchy (Visual)](#configuration-hierarchy-visual)
  - [Standalone Mode](#standalone-mode)
    - [Start with SSL (default)](#start-with-ssl-default)
    - [Start without SSL (for Apache reverse proxy)](#start-without-ssl-for-apache-reverse-proxy)
  - [Apache Reverse Proxy Mode](#apache-reverse-proxy-mode)
    - [Running multiple http\_server.py](#running-multiple-http_serverpy)
    - [Apache VirtualHost configuration](#apache-virtualhost-configuration)
    - [httpd-proxy-ota.conf:](#httpd-proxy-otaconf)
  - [JWT-Based Authentication for OTA Access](#jwt-based-authentication-for-ota-access)
    - [Token Generation](#token-generation)
    - [JWT Payload Fields](#jwt-payload-fields)
    - [JWT Generation Logic](#jwt-generation-logic)
    - [Token Usage (Devices)](#token-usage-devices)
    - [Audit Logging](#audit-logging)
    - [Security Notes](#security-notes)
  - [Favicon](#favicon)
    - [Example OTA Firmware URL](#example-ota-firmware-url)
  - [Code Quality and Static Analysis](#code-quality-and-static-analysis)
    - [🧠 Type Checking with `mypy`](#-type-checking-with-mypy)
    - [🧹 Code Linting with pylint](#-code-linting-with-pylint)
    - [🧩 `mypy` vs `pylint` — Comparison Overview](#-mypy-vs-pylint--comparison-overview)
    - [✅ Summary](#-summary)


A lightweight Python/Flask-based firmware server for Over-The-Air (OTA) updates.
The project is organized as a `pyproject.toml` `poetry` driven project.
Supports optional **JWT-based authentication** and can run in two modes:

- **Standalone mode** — Flask runs directly (with optional SSL)
- **Reverse proxy mode** — Behind Apache (HTTP or HTTPS) with load balancing

---

## 🗺 Architecture

```
          +------------------------+
          |      OTA Client        |
          | (ESP32, etc.)          |
          +-----------+------------+
                      |
                      v
          +------------------------+
          |   Apache HTTP Server    |
          |  - SSL Termination      |
          |  - Reverse Proxy        |
          |  - Load Balancer        |
          +-----------+------------+
                      |
      +---------------+---------------+
      |               |               |
      v               v               v
+-------------+ +-------------+ +-------------+
|  Flask App  | |  Flask App  | |  Flask App  |
|    (8071)   | |    (8072)   | |    (8073)   |
+-------------+ +-------------+ +-------------+
                      |
                      v
 +-------------------------------------------+
 | Firmware Files (www/<project>/<bin file>) |
 |  url path /firmware/<project>/<bin file>  |
 +-------------------------------------------+
```

---

## 🚀 Quick Start (source installation)

### Prerequisites

1. Install `Python version >= 3.12`
2. Install pipx
3. Using pipx install poetry.

### Installing `ota_http_server` as a editable project

1. Clone teh repository from https://github.com/jwalkerbg/ota_http_server.git.
2. Execute `poetry install -vvv` in the repository root.
3. Activate python environment with `poetry env activate`. The will activate the environment or emit a command that shall be executed.

### Run the server.

1. **Run the server (no SSL)**:
```bash
python http_server.py --no-certs --port 8071
```

## Features

* Serve firmware files from a defined directory structure
* Optional JWT token authentication (Authorization: Bearer <JWT> or ?token=<JWT>)
* JWT Token generation through administrative route with admin token/password
* HTTPS support in standalone mode
* Easy integration behind Apache reverse proxy
* Built-in favicon.ico serving
* Load balancing for multiple Flask instances

## Editable project - directory Structure

```
project_root/
├── src/
│   └── ota_http_server
│       ├── cli/
│       ├── core/
│       ├── logger/
│       └── extensions/
├── tests/
├── certs/
│   ├── gen
│   ├── gen.bat
├── www/
│   ├── favicon.ico
│   └── firmware/
│       ├── projectA/
│       │   └── firmware_v1.bin
│       └── projectB/
│           ├── firmware_v1.bin
│           └── firmware_v2.bin
├── build.py
├── pyproject.toml
├── config.toml
├── ota_start.bat
└── README.md
```

## Configuration

The `OTA HTTP Server` is fully configurable with a `four-level configuration hierarchy`, from lowest-priority defaults to highest-priority overrides:

### Default Hardcoded Values (Lowest Priority).

The server ships with `built-in default values` for all configuration parameters. These serve as a fallback when no other configuration source provides a value.

Example defaults include:

* JWT algorithm: "HS256"
* JWT expiry: 30 minutes
* Audit log file: "ota_audit.log"
* Firmware directories: "firmware", "www"

### Configuration File (`config.toml`)

Users can override defaults by providing a `TOML configuration file` (`config.toml`). This allows persistent, project-wide configuration without touching the CLI.

Example `config.toml`:
```
[parameters]
host = "0.0.0.0"
port = 8080
no_certs = false
no_jwt = false
jwt_alg = "HS512"
jwt_expiry = 60
jwt_secret = "supersecret"
admin_secret = "adminsecret"
www_dir = "www"
firmware_dir = "firmware"
url_firmware = "firmware"
ota_audit_log = "ota_audit.log"
```
Note: In the configuration file, keys use `underscores` (`_`), while the corresponding CLI options use `hyphens` (`-`).

### Environment Variables.

For `dynamic runtime overrides`, the server can read environment variables. These are read on server start only, not on every http(s) request afterwards. These take precedence over values defined in `config.toml`. These variables are as follows:

* "jwt_alg": os.getenv("OTA_JWT_ALGORITHM"),
* "jwt_expiry": os.getenv("OTA_JWT_EXPIRY_MINUTES"),
* "jwt_secret": os.getenv("OTA_JWT_SECRET"),
* "admin_secret": os.getenv("OTA_ADMIN_SECRET"),
* "ota_audit_log": os.getenv("OTA_AUDIT_LOG")

Above is a code snippet from `core/config.py` and correspondence between the `environment variables` and the `options` can be seen.

Note: Environment variables allow system-level or containerized overrides without editing files.

### Command-Line Options (Highest Priority)

The `CLI options` override all other configuration sources. This is ideal for temporary adjustments or one-off executions.

Example usage:

```
ota_http_server --host 0.0.0.0 --port 8071 --no-certs --no-jwt --jwt-expiry 5
```

### Configuration Hierarchy (Visual)

Highest priority → Lowest priority:

```
CLI Options        → override everything
    ↑
Environment Vars   → override config.toml & defaults
    ↑
config.toml        → override hardcoded defaults
    ↑
Default Hardcoded  → fallback values
```

## Standalone Mode

You can run the server directly with Python.

### Start with SSL (default)

```bash
python http_server.py \
    --cert certs/ca_cert.pem \
    --key certs/ca_key.pem \
    --host 0.0.0.0 \
    --port 8070 \
    --www-dir www \
    --firmware-dir firmware \
    --url-firmware firmware
```

### Start without SSL (for Apache reverse proxy)

```bash
python http_server.py --no-certs --port 8071
```

Execute `ota_http_server --help` to see all options.

See the virtual host and reverse proxy configurations to figure out ports usage.

If `--no-jwt` option is given JWT token is not used even it is supplied in the header Bearer or at the end of the url.

## Apache Reverse Proxy Mode

### Running multiple http_server.py

You can place multiple instances of ```http_server.py``` behind Apache for load balancing.

```bash
python http_server.py --no-certs --port 8071
python http_server.py --no-certs --port 8072
python http_server.py --no-certs --port 8073
```

### Apache VirtualHost configuration

```
Listen 8070

<IfModule !mod_ssl.c>
LoadModule ssl_module lib/modules/mod_ssl.so
</IfModule>

<VirtualHost *:8070>
    ServerName mycompany.com

    SSLEngine on
    SSLCertificateFile "E:/data/https_server/certs/mycompany.com-chain.pem"
    SSLCertificateKeyFile "E:/data/https_server/certs/mycompany.com-key.pem"

    Include e:/data/vhosts/httpd-proxy-ota.conf

    ErrorLog e:/data/log/ota.error.log
    TransferLog e:/data/log/ota.transfer.log
</VirtualHost>
```

The certificate CN field must be the same as the domain name in the url.

### httpd-proxy-ota.conf:

```
<IfModule !mod_lbmethod_byrequests.c>
    LoadModule lbmethod_byrequests_module lib/modules/mod_lbmethod_byrequests.so
</IfModule>
<IfModule !mod_proxy.c>
    LoadModule proxy_module lib/modules/mod_proxy.so
</IfModule>
<IfModule !mod_proxy_http.c>
    LoadModule proxy_http_module lib/modules/mod_proxy_http.so
</IfModule>
<IfModule !mod_proxy_balancer.c>
    LoadModule proxy_balancer_module lib/modules/mod_proxy_balancer.so
</IfModule>

ProxyPreserveHost On

<Proxy "balancer://flaskcluster">
    BalancerMember http://127.0.0.1:8071
    #BalancerMember http://127.0.0.1:8072
    #BalancerMember http://127.0.0.1:8073
    ProxySet lbmethod=byrequests
</Proxy>

ProxyPass "/" "balancer://flaskcluster/"
ProxyPassReverse "/" "balancer://flaskcluster/"
```

3. Authentication

JWT authentication is enabled by default. Clients can pass JWT in the header or as an URL parameter.

```
GET /firmware/projectA/firmware_v1.bin?token=<JWT>
```

## JWT-Based Authentication for OTA Access

The OTA server uses JSON Web Tokens (JWTs) instead of static tokens.
Each device (ESP32, etc.) must present a valid JWT when requesting firmware files or version information.

JWTs are short-lived, cryptographically signed tokens that the OTA server verifies using a secret key.
This improves security, enables per-device authorization, and supports expiration and revocation.

By default JWT tokens are used. The OTA server may be commanded to not use them with the command line option `--no-jwt`.

### Token Generation

Tokens are issued dynamically via the admin endpoint:

```html
POST /admin/generate_token
```
**Request headers**

Header | Description
-------|------------
| X-Admin-Secret | The administrator secret (must match the server’s ADMIN_SECRET environment variable). |
| Content-Type | Must be application/json. |

**Request body**
```json
{
  "device_id": "e6f87d77-4216-4be1-ab83-b5fa6792b747",
  "project": "smart_fan",
  "expires_minutes": 30,
  "current_fw": "1.0.0"
}
```
* `device_id` — The unique UUID of the device that will perform OTA.
* `project` — The firmware project name (must match the folder name under /firmware/).
* `expires_minutes` (optional) — Token lifetime in minutes (default: value of JWT_DEFAULT_EXPIRY_MINUTES).
* `current_fw` (optional) — Current firmware version; stored in the token for auditing.

**Example curl command (Linux/macOS)**
```bash
curl -X POST https://yourserver:8070/admin/generate_token \
  -H "X-Admin-Secret: $OTA_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
        "device_id": "e6f87d77-4216-4be1-ab83-b5fa6792b747",
        "project": "smart_fan"
      }'
```

The response contains a signed JWT and metadata:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",
  "expires_at": "2025-10-09T15:34:12+00:00",
  "payload": {
    "sub": "e6f87d77-4216-4be1-ab83-b5fa6792b747",
    "project": "smart_fan",
    "roles": ["device", "ota_client"],
    "iat": 1739083200,
    "exp": 1739085000,
    "jti": "e6f87d77-4216-4be1-ab83-b5fa6792b747-1739083200",
    "fw_version": "1.0.0"
  }
}
```

### JWT Payload Fields

Field | Description
------|------------
| `sub` | Device unique identifier (UUIDv4). Identifies which device the token belongs to. |
| `project` | Project name — firmware group or directory name. Used to verify access. |
| `roles` | List of logical roles; currently includes "device" and "ota_client". |
| `iat` | Issued-At timestamp (UNIX time). |
| `exp` | Expiration time — after this the token becomes invalid. |
| `jti` | Unique token ID (JWT ID). Helps detect re-use or revoke individual tokens. |
| `fw_version` | Current firmware version reported when the token was generated. |

### JWT Generation Logic

Internally, the server uses:

```python
def generate_ota_jwt(device_id, project, current_fw="1.0.0",
                     expires_minutes=JWT_DEFAULT_EXPIRY_MINUTES):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": device_id,
        "project": project,
        "roles": ["device", "ota_client"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "jti": f"{device_id}-{int(now.timestamp())}",
        "fw_version": current_fw
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM), payload
```

### Token Usage (Devices)

Each OTA-capable device must include its token in every request to the OTA server:

**Authorization header**

```html
Authorization: Bearer <jwt_token_here>
```
or equivalently as a query parameter:
```
?token=<jwt_token_here>
```

**Example firmware download**

```html
GET /firmware/projectA/projectA-01.00.02.bin
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
or
```html
GET /firmware/projectA/projectA-01.00.02.bin?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Audit Logging

Each successful token generation is logged for traceability:

```
[2025-10-09T15:34:12Z] [AUDIT] Action=generate_token IP=203.0.113.7 device=e6f87d77-4216-4be1-ab83-b5fa6792b747 project=projectA exp=1739085000
```

This allows tracking which admin generated which tokens and when.

### Security Notes

* The admin secret (X-Admin-Secret) must never be hardcoded.
It is read from the environment variable `OTA_ADMIN_SECRET`.
Set it securely before starting the server:

```bash
Linux:
export OTA_ADMIN_SECRET="your-very-long-secret-value"
```
```bash
Windows:
setx OTA_ADMIN_SECRET "your-very-long-secret-value"
```
* Always use HTTPS when issuing or using tokens.
* Tokens are short-lived by design; keep expiry short (5–60 minutes).
* Devices should request a new token only when needed, not store them permanently.

## Favicon

The server automatically serves ```/favicon.ico``` from the ```www/``` directory if present.
Browsers usually cache this file, so it will only be requested once. Devices initiating OTA do not request ```favicon.ico```.

### Example OTA Firmware URL

With token
```bash
https://mycompany.com/firmware/projectA/firmware_v1.bin?token=<JWT>
```

Without token
```bash
https://mycompany.com/firmware/projectA/firmware_v1.bin
```

## Code Quality and Static Analysis

This project uses **static analysis** tools to ensure consistent, clean, and type-safe Python code.
All tools are fully integrated with **Poetry**, so they can be run directly from the project environment.

---

### 🧠 Type Checking with `mypy`

[`mypy`](https://mypy.readthedocs.io/) performs **static type checking** for Python.
It validates type hints, detects inconsistencies, and helps prevent many runtime errors.

**Configuration** is defined in `pyproject.toml` under the `[tool.mypy]` section.

Example configuration:
```toml
[tool.mypy]
python_version = "3.13"
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
strict_optional = true
check_untyped_defs = true
show_error_codes = true
pretty = true

[[tool.mypy.overrides]]
module = ["tests.*"]
ignore_errors = true
```
See `mypy` sections in `pyproject.toml` too.

Usage:

```bash
poetry run mypy --strict
```

✅ Good practice:

* Always include type hints for all function parameters and return types.
* Use `dict[str, Any]` instead of `Dict` for new code.
* Use `Optional[T]` or `T | None` for nullable types.

### 🧹 Code Linting with pylint

`pylint` checks for `style, formatting, and common logic issues`.
It enforces coding conventions (PEP 8) and helps maintain consistent quality across the project.

`Configuration` is defined in `pyproject.toml` under `[tool.pylint]`.

Example configuration:

```toml
[tool.pylint.'MESSAGES CONTROL']
disable = [
    "missing-module-docstring",
    "missing-class-docstring",
    "missing-function-docstring"
]

[tool.pylint.BASIC]
good-names = ["i", "j", "k", "x", "y", "z", "cfg"]

[tool.pylint.FORMAT]
max-line-length = 100
```

**Usage:**

```bash
poetry run pylint src/ota_http_server
```

✅ **Good practice:**

* Fix reported warnings progressively — not everything needs to be perfect at once.
* Use clear variable names and keep functions small and focused.
* Disable specific warnings sparingly, using inline comments (e.g. `# pylint: disable=too-many-locals`).

🧩 **Integration Tips**

* Both tools can run in `CI/CD pipelines` or `pre-commit hooks` to automatically enforce quality.
* You can run both together:

```bash
poetry run mypy --strict && poetry run pylint src/ota_http_server
```

* For local development, most editors (including `VS Code`) support real-time integration with both `mypy` and `pylint`.

⚙️ **Why This Matters**

These tools teach and enforce good engineering habits:

* `mypy` helps think in `types and contracts`
* `pylint` promotes `clarity and maintainability`
* Combined, they create a foundation for `professional, production-ready Python`

🧭 This project intentionally includes both tools so that it presents practices for structuring, typing, and linting real-world Python code.

### 🧩 `mypy` vs `pylint` — Comparison Overview

| Feature / Aspect                     | 🧠 **mypy**                                            | 🧹 **pylint**                                             |
|-------------------------------------|--------------------------------------------------------|-----------------------------------------------------------|
| **Main Purpose**                    | Static **type checking**                              | Static **code style and logic checking**                  |
| **Focus**                           | Type correctness, annotations, consistency             | Code quality, readability, and common mistakes            |
| **Analyzes**                        | Type hints (`int`, `str`, `dict[str, Any]`, etc.)      | Code structure, naming, formatting, and logic patterns    |
| **Detects Issues Like**             | - Type mismatches<br>- Missing return types<br>- Invalid assignments | - Unused variables<br>- Bad naming<br>- Missing docstrings<br>- Complex functions |
| **Driven by**                       | Type annotations (`PEP 484`, `PEP 561`)                | PEP 8 style guide and internal rules                      |
| **Requires Type Hints**             | ✅ Yes — essential for accurate checking               | ⚙️ No — works even without type hints                     |
| **Output Example**                  | `error: Incompatible types in assignment`              | `warning: Unused variable 'temp'`                         |
| **Configuration Section**           | `[tool.mypy]`                                          | `[tool.pylint]`                                           |
| **Strict Mode Available**           | ✅ `--strict`                                           | ⚙️ Configurable rules via disable/enable lists             |
| **Integration with Editors**        | Excellent (VS Code, PyCharm, etc.)                     | Excellent (VS Code, PyCharm, etc.)                        |
| **When to Use**                     | To **validate type correctness** before runtime        | To **enforce coding standards** and catch bad patterns    |
| **Example Command**                 | `poetry run mypy --strict`                             | `poetry run pylint src/ota_http_server`                   |
| **Typical Output Tone**             | Precise and technical                                  | Descriptive and advisory                                  |
| **Teaches You**                     | Thinking in **data types and contracts**               | Writing **clean, maintainable Python code**               |
| **Recommended Usage**               | Always run before linting                              | Run after mypy to check code style and structure           |

---

### ✅ Summary

- **Use `mypy`** to ensure your types and interfaces are correct.
- **Use `pylint`** to ensure your code is clean, readable, and follows conventions.
- Together, they form a **complete quality gate** for professional Python development.
