# OTA Firmware Server

- [OTA Firmware Server](#ota-firmware-server)
  - [🗺 Architecture](#-architecture)
  - [🚀 Quick Start (source installation)](#-quick-start-source-installation)
    - [Prerequisites](#prerequisites)
    - [Installing `ota_http_server` as a editable project](#installing-ota_http_server-as-a-editable-project)
    - [Producing distributable package](#producing-distributable-package)
    - [Run the server.](#run-the-server)
  - [Features](#features)
  - [Editable project - directory Structure](#editable-project---directory-structure)
  - [Configuration](#configuration)
    - [Default Hardcoded Values (Lowest Priority).](#default-hardcoded-values-lowest-priority)
    - [Configuration File (`config.toml`)](#configuration-file-configtoml)
    - [Environment Variables.](#environment-variables)
    - [Command-Line Options (Highest Priority)](#command-line-options-highest-priority)
    - [Configuration Hierarchy (Visual)](#configuration-hierarchy-visual)
  - [Structure of OTA URL](#structure-of-ota-url)
  - [Standalone Mode](#standalone-mode)
    - [Start with SSL (default)](#start-with-ssl-default)
    - [Start without SSL (for Apache reverse proxy)](#start-without-ssl-for-apache-reverse-proxy)
  - [Apache Reverse Proxy Mode](#apache-reverse-proxy-mode)
    - [Running multiple ota\_http\_server](#running-multiple-ota_http_server)
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
 |   url path /firmware/<project>/<version>  |
 +-------------------------------------------+
```

---

## 🚀 Quick Start (source installation)

### Prerequisites

1. Install `Python version >= 3.12`
2. Install pipx
   1. pip install pipx
   2. pipx ensurepath
3. Using pipx install poetry.
   1. pipx install poetry

### Installing `ota_http_server` as a editable project

1. Clone the repository from https://github.com/jwalkerbg/ota_http_server.git.
2. Execute `poetry update`
3. Execute `poetry install -vvv` in the repository root.
4. Activate python environment with `poetry env activate`. The command will activate the environment or emit a command that shall be executed. This activates editable environment for developers.

### Producing distributable package

1. Execute `poetry build -vvv` in the repository root. This will produce distributable packages in `dist` subfolder.
2. Open new shell and execute `cd dist` then `pipx install ota_http_server-3.0.1-cp314-cp314-win_amd64.whl` (if executed in Windows environment). See the exact name of the `whl` file. This will install `ota_http_server` system wide. Similar command will install the server in Linux environment. Remember: use `pipx`, not `pip`. If you want to see what `pipx` does execute `pipx` with option `-vvv`.

### Run the server.

1. **Run the server**:
```bash
ota_http_server --help
```

## Features

* Serve firmware files from a defined directory structure
* Optional JWT token authentication (Authorization: Bearer <JWT> or ?token=<JWT>)
* JWT Token generation through administrative route with admin token/password
* HTTPS support in standalone mode
* Easy integration behind Apache reverse proxy
* Built-in favicon.ico serving
* Load balancing for multiple Flask instances

## Database

The application keeps firmware and metadata in a relational database. By default it uses SQLite (`ota_db.sqlite`), but the project also supports a MySQL backend through the `database` configuration section. The database model is centered around four main entities: users, projects, devices, and firmware records.

### Users

The `users` table stores application accounts used for authentication and access control.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Internal row identifier |
| `username` | TEXT | Unique account name |
| `password_hash` | TEXT | Stored as a hash, never as plaintext |
| `email` | TEXT | Unique email address |
| `role` | TEXT | Role-based access control (`admin`, `operator`, `viewer`) |
| `is_active` | INTEGER | `1` = enabled, `0` = disabled |
| `created_at` | TEXT | Created timestamp |
| `updated_at` | TEXT | Last modification timestamp |

The `users` table is the parent record for project ownership and for any future admin actions tied to a specific operator.

### Projects

The `projects` table groups firmware releases into logical product families.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Internal row identifier |
| `name` | TEXT | Unique project key, used in URLs and lookups |
| `display_name` | TEXT | Human-readable project label |
| `description` | TEXT | Optional description |
| `created_by` | INTEGER | Foreign key to `users.id` |
| `is_active` | INTEGER | `1` = enabled, `0` = disabled |
| `created_at` | TEXT | Created timestamp |
| `updated_at` | TEXT | Last modification timestamp |

A project belongs to a single creator user and may be enabled or disabled without deleting its history.

### Devices

The `devices` table tracks hardware instances that are allowed to receive OTA updates. In the application layer the identifier is exposed as a UUID-style device ID, but the database column is represented as `device_id`.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Internal row identifier |
| `device_id` | TEXT | Unique device identifier (UUID or similar) |
| `project_id` | INTEGER | Foreign key to `projects.id` |
| `model` | TEXT | Device model name |
| `serial_number` | TEXT | Optional manufacturer serial number |
| `current_version` | TEXT | Last known firmware version |
| `last_seen` | TEXT | Last time the device contacted the server |
| `is_active` | INTEGER | `1` = active, `0` = disabled |
| `created_at` | TEXT | Created timestamp |
| `updated_at` | TEXT | Last modification timestamp |

The schema enforces a unique `device_id`, and the `serial_number` column also has a unique partial index when it is not null.

### Firmware

The `firmware` table stores binary metadata for each project version. Each row represents a specific version and channel combination.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Internal row identifier |
| `project_id` | INTEGER | Foreign key to `projects.id` |
| `version` | TEXT | Firmware version label |
| `filename` | TEXT | File name stored on disk |
| `file_size` | INTEGER | File size in bytes |
| `checksum` | TEXT | Checksum for integrity validation |
| `release_notes` | TEXT | Optional release notes |
| `channel` | TEXT | `stable`, `beta`, or `dev` |
| `created_at` | TEXT | Created timestamp |
| `updated_at` | TEXT | Last modification timestamp |

The table contains a unique constraint on `(project_id, version, channel)` so a project cannot register the same version twice on the same channel.

## Database Migrations

The database schema is versioned through Python migration scripts located in `src/ota_http_server/database/migrations/sqlite` (and the MySQL migration directory for MySQL deployments).

Migration files follow the naming convention:

```text
NNN_name_of_migration.py
```

Example:

```text
001_create_user_table.py
002_create_projects_table.py
003_create_devices_table.py
004_create_firmware_table.py
```

Each migration implements an `up(conn)` method to apply schema changes and a `down(conn)` method to roll them back. The runner maintains a `schema_version` table to record the latest successfully applied migration.

Typical migration commands are:

```bash
ota_http_server db init-db --migrate
ota_http_server db migrate
ota_http_server db migrate --dry-run
ota_http_server db rollback
ota_http_server db rollback --all
```

`db init-db` creates the database if needed; with `--migrate` it applies the migration set immediately. `db migrate` runs any pending migrations in order. `db rollback` reverts the most recent migration, while `--all` rolls back all applied migrations.

## Command-Line Interface

The project exposes a single entry-point command named `ota_http_server` with subcommands for server startup, database maintenance, and CRUD operations for users, projects, devices, and firmware.

### Global and server options

Common entry points include:

```bash
ota_http_server --help
ota_http_server runserver --help
```

Server configuration options include host, port, certificate settings, JWT flags, and database connection parameters. The database can be selected with `--dbtype` (`sqlite` or `mysql`), while SQLite file path is controlled with `--dbfile`.

### Database operations

```bash
ota_http_server db init-db --migrate
ota_http_server db migrate --dry-run
ota_http_server db rollback --all
```

These commands are used to prepare the database and to keep the schema synchronized with the codebase.

### User operations

```bash
ota_http_server user add --name admin --password secret --email admin@example.com --role admin
ota_http_server user list --record
ota_http_server user list --enabled
ota_http_server user get --username admin
ota_http_server user enable --user-id 1
ota_http_server user disable --username admin
```

User records support creation, retrieval, listing, and activation/deactivation.

### Project operations

```bash
ota_http_server project add --name smart_home --display_name "Smart Home" --description "Main project" --created-by 1
ota_http_server project list --record
ota_http_server project get --name smart_home
ota_http_server project enable --id 1
ota_http_server project disable --name smart_home
```

Projects group firmware and devices, and each project can be enabled or disabled independently.

### Device operations

```bash
ota_http_server device add --uuid 11111111-2222-3333-4444-555555666666 --pid 1 --model ESP32 --sn ABC123 --version 1.2.0
ota_http_server device list --pid 1
ota_http_server device get --uuid 11111111-2222-3333-4444-555555666666
ota_http_server device enable --id 1
ota_http_server device disable --uuid 11111111-2222-3333-4444-555555666666
```

Devices are associated with a project and maintain their current firmware version and last-seen status.

### Firmware operations

```bash
ota_http_server firmware add --pid 1 --version 1.2.0 --file firmware_v1_2_0.bin --notes "Bug fixes" --channel stable
ota_http_server firmware list --pid 1
ota_http_server firmware get --pid 1 --version 1.2.0
ota_http_server firmware enable --pid 1 --version 1.2.0
ota_http_server firmware disable --id 2
ota_http_server firmware replace --id 2 --file firmware_v1_2_1.bin
```

Firmware records include release metadata, binary checksum information, and active/inactive status for OTA distribution.

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
├── ota_db.toml
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
* "jwt_expiry": os.getenv("OTA_JWT_EXPIRY_SECONDS"),
* "jwt_max_expiry": os.getenv("OTA_JWT_MAX_EXPIRY_SECONDS"),
* "jwt_secret": os.getenv("OTA_JWT_SECRET"),
* "admin_secret": os.getenv("OTA_ADMIN_SECRET"),
* "ota_audit_log": os.getenv("OTA_AUDIT_LOG")
* "jwt_issuer": os.getenv("OTA_JWT_ISSUER"),
* "jwt_audience": os.getenv("OTA_JWT_AUDIENCE"),
* "ota_db": os.getenv("OTA_DATABASE"),
* "ota_db_cache_ttl": os.getenv("OTA_DB_CACHE_TTL")

Above is a code snippet from `core/config.py` and correspondence between the `environment variables` and the `options` can be seen.

Note: Environment variables allow system-level or containerized overrides without editing files.

### Command-Line Options (Highest Priority)

The `CLI options` override all other configuration sources. This is ideal for temporary adjustments or one-off executions.

Example usage:

```
ota_http_server --host 0.0.0.0 --port 8071 --no-certs --no-jwt
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

## Structure of OTA URL

This is an example URL:

`https://ota.mycompany.com:8070/firmware/projectA/01.00.02?token=<JWT>`

Use `/<url_firmware>/<project>/<version>` as the canonical request format.

`https://ota.mycompany.com:8070/firmware/projectA/projectA-01.00.02.bin?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

The server root directory is `www` by default, relative to the directory where OTA server is started. It can be changed in `config.toml` with the parameter `www_dir` or with the CLI option `--www-dir`.

Next level directory must present below `www` that is a container for the firmware files for all projects. By default it is `firmware`. It corresponds to te first element in URL after the domain and port.
The directory name in the file system can be changed by `firmware_dir` parameter (`--firmware-dir` option). The first element in the URL path can be changed / renamed by `url_firmware` parameter (`--url-firmware`).

Next element in the URL is the project name. If JWT is used it must be the same with the value of `project` field in JWT.

After the project name firmware version follows. The server resolves the
version to the real binary image file name using firmware metadata in the
database.

An eventual JWT is at the end.

## Standalone Mode

You can run the server directly with Python.

### Start with SSL (default)

```bash
ota_http_server \
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
ota_http_server --no-certs --port 8071
```

Execute `ota_http_server --help` to see all options.

See the virtual host and reverse proxy configurations to figure out ports usage.

If `--no-jwt` option is given JWT token is not used even it is supplied in the header Bearer or at the end of the url.

## Apache Reverse Proxy Mode

### Running multiple ota_http_server

You can place multiple instances of ```ota_http_server``` behind Apache for load balancing.

```bash
ota_http_server --no-certs --port 8071
ota_http_server --no-certs --port 8072
ota_http_server --no-certs --port 8073
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
GET /firmware/projectA/01.00.02?token=<JWT>
```

## JWT-Based Authentication for OTA Access

The OTA server supports JWT-based access control for firmware downloads and version lookups. JWT authentication is enabled by default; it can be disabled with `--no-jwt` or the configuration flag `no_jwt = true`.

The current implementation enforces the token on the OTA endpoints that serve firmware and metadata:

- `/firmware/<project>/<version>`
- `/firmware/<project>/latest`
- `/firmware/<project>/versions`

The security model is intentionally strict:

- the token must be valid and unexpired
- the token must match the requested project
- the token must have the required roles (`device`, `fw_download`)
- the audience and issuer must match the configured values
- the token subject (`sub`) must match the client identity (`X-Device-ID` header or `?device_id=` query parameter)

### Token format and trust model

JWTs are created by the server on demand and signed with the configured secret and algorithm. The actual implementation verifies the token using the configured `jwt_secret`, `jwt_algorithm`, `jwt_issuer`, and `jwt_audience` values.

The verification flow in the current code allows:

- `Authorization: Bearer <token>`
- `?token=<token>` for `GET` and `HEAD` requests only

For non-safe HTTP methods, query-string tokens are rejected with `405`.

### Token generation

Tokens are issued dynamically via the admin endpoint:

```http
POST /admin/generate_token
```

Required headers:

| Header | Required | Description |
| --- | --- | --- |
| `X-Admin-Secret` | Yes | Matches the configured server secret, usually stored in `OTA_ADMIN_SECRET` |
| `Content-Type` | Yes | Must be `application/json` |

Request body:

```json
{
  "device_id": "e6f87d77-4216-4be1-ab83-b5fa6792b747",
  "project": "smart_fan",
  "expires_seconds": 300,
  "current_vs": "1.0.0",
  "download_vs": "2.0.0"
}
```

Fields in the request body:

- `device_id` — UUID for the device that will use the token
- `project` — Target project name, must match the OTA project
- `expires_seconds` — Optional, token lifetime in seconds; the server caps it by `jwt_max_expiry`
- `current_vs` — Optional current device firmware version; accepted by the API but not included in the token payload in the current implementation
- `download_vs` — Required; this is the firmware version the token authorizes the device to download

The server currently enforces a minimum validation set:

- `device_id` must be a valid UUID
- `project` must be provided
- `download_vs` must be provided
- `expires_seconds` is clamped to `jwt_max_expiry`

Example:

```bash
curl -X POST https://yourserver:8070/admin/generate_token \
  -H "X-Admin-Secret: $OTA_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
        "device_id": "e6f87d77-4216-4be1-ab83-b5fa6792b747",
        "project": "smart_fan",
        "expires_seconds": 300,
        "current_vs": "1.0.0",
        "download_vs": "2.0.0"
      }'
```

The response is a JSON object containing the signed JWT and the payload used to generate it:

```json
{
  "token": "eyJ...",
  "expires_at": "2026-08-19T14:00:00+00:00",
  "payload": {
    "aud": "ota_api",
    "exp": 1755585600,
    "current_vs": "1.0.0",
    "download_vs": "2.0.0",
    "iat": 1755585000,
    "iss": "ota_http_server",
    "jti": "e6f87d77-4216-4be1-ab83-b5fa6792b747-1755585000",
    "project": "smart_fan",
    "roles": [
      "device",
      "fw_download"
    ],
    "sub": "e6f87d77-4216-4be1-ab83-b5fa6792b747"
  }
}
```

### JWT claims used by the current implementation

The current code verifies and relies on these claims:

| Claim | Meaning |
| --- | --- |
| `aud` | Target audience, must match `jwt_audience` (default: `ota_api`) |
| `exp` | Expiration timestamp; token is rejected when expired |
| `iat` | Issued-at timestamp |
| `iss` | Issuer, must match `jwt_issuer` (default: `ota_http_server`) |
| `jti` | Unique identifier of the generated token |
| `project` | Project name the token is valid for |
| `roles` | Must contain both `device` and `fw_download` |
| `sub` | Device identity; must match the `X-Device-ID` header or `device_id` query parameter |
| `current_vs` | Device firmware version at token creation time |
| `download_vs` | Version the token authorizes the device to download |

The `current_vs` claim is now included in the token payload so the token carries both the device’s current firmware version and the authorized target version.

### Token verification rules

When a request reaches an OTA endpoint, the server does the following:

1. Reads the token from `Authorization: Bearer ...` or `?token=...`
2. Verifies the signature and expiry using the configured secret and algorithm
3. Checks the `aud` claim against `jwt_audience`
4. Checks the `iss` claim against `jwt_issuer`
5. Confirms the token is for the requested project
6. Enforces required roles: `device`, `fw_download`
7. Verifies the `sub` claim matches the device identifier supplied by the client
8. Allows the request only if the device is registered for that project and active

### Token usage by devices

A device should send the token as a bearer token in the HTTP header when possible:

```http
GET /firmware/projectA/1.2.0
Authorization: Bearer <jwt>
X-Device-ID: e6f87d77-4216-4be1-ab83-b5fa6792b747
```

For `GET` and `HEAD` requests, a query-string token is also accepted:

```http
GET /firmware/projectA/1.2.0?token=<jwt>&device_id=e6f87d77-4216-4be1-ab83-b5fa6792b747
```

The server does not permit query string tokens for non-safe methods.

### Version metadata endpoints

The server exposes project metadata endpoints that can also be protected by JWT verification:

```http
GET /firmware/projectA/latest
GET /firmware/projectA/versions
```

The `/versions` endpoint verifies the token with `verify_sub=False`, which means a valid token can be used to read the available versions, but the device identity is not required for that specific call.

### Audit logging

Token generation is logged for traceability. On success the server records an audit event with the device ID, project, and expiration time.

Example log entry:

```text
[2026-08-19T14:00:00+00:00] [AUDIT] device=e6f87d77-4216-4be1-ab83-b5fa6792b747 project=smart_fan exp=1755585600
```

### Security notes

- Keep `OTA_ADMIN_SECRET` out of source control; prefer environment variables or secret stores
- Always use HTTPS in production when issuing and consuming tokens
- Use short expirations (for example 5–60 minutes) and rotate secrets as part of operational hygiene
- Do not reuse tokens across devices or projects
- Prefer `Authorization: Bearer ...` over query parameters, because query parameters are less safe and are limited to `GET`/`HEAD`

### Recommended additions and implementation notes

The JWT flow is now aligned with the codebase:

1. `download_vs` is the effective authorization version for the OTA transfer
2. `current_vs` is recorded in the JWT payload when the token is issued, so the device state is preserved with the authorization grant
3. `sub` must match the `X-Device-ID` header or `device_id` query parameter
4. `?token=` is accepted only for safe methods (`GET` and `HEAD`)
5. `expires_seconds` is capped by `jwt_max_expiry` before the token is signed
6. Future revocation and rotation policies can still be added later, but the current token model is now explicit and auditable
## Favicon

The server automatically serves ```/favicon.ico``` from the ```www/``` directory if present.
Browsers usually cache this file, so it will only be requested once. Devices initiating OTA do not request ```favicon.ico```.

### Example OTA Firmware URL

With token
```bash
https://mycompany.com/firmware/projectA/01.00.02?token=<JWT>
```

Without token
```bash
https://mycompany.com/firmware/projectA/01.00.02
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
