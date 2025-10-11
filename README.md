# OTA Firmware Server

- [OTA Firmware Server](#ota-firmware-server)
  - [🗺 Architecture](#-architecture)
  - [🚀 Quick Start](#-quick-start)
  - [Features](#features)
  - [Directory Structure](#directory-structure)
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


A lightweight Python/Flask-based firmware server for Over-The-Air (OTA) updates.
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
       +-------------------------------+
       |     Firmware Files (www/)     |
       |/firmware/<project>/<bin file> |
       +-------------------------------+
```


---

## 🚀 Quick Start

1. **Clone or copy the files** into a working directory.
2. Create local python environment (Python 3.13+ required)
```bash
python -m venv .venv
.venv\Scripts\activate.bat
```
3. **Install dependencies**:
```bash
pip install flask packaging PyJWT
```
4. Create directories:
```bash
mkdir -p www\firmware\projectA
```
5. Add a firmware file:
```bash
echo "dummy firmware data" > www\firmware\projectA\firmware_v1.bin
```
6. Add a favicon (optional but recommended):
```bash
# Example: copy any 16x16 or 32x32 .ico file
copy my_favicon.ico www\favicon.ico
# Example: copy any 16x16 or 32x32 .ico file
copy my_favicon.ico www/favicon.ico
7. Run the server (no SSL):
```bash
python http_server.py --no-certs --port 8071
```
8. Access firmware:
```bash
http://localhost:8071/firmware/projectA/firmware_v1.bin?token=JWT_token
```

## Features

* Serve firmware files from a defined directory structure
* Optional JWT token authentication (Authorization: Bearer <JWT> or ?token=<JWT>)
* HTTPS support in standalone mode
* Easy integration behind Apache reverse proxy
* Built-in favicon.ico serving
* Load balancing for multiple Flask instances

## Directory Structure

```
project_root/
├── .venv
├── http_server.py
├── ota_start.bat
├── certs/
│   ├── ca_cert.pem
│   ├── ca_key.pem
├── www/
│   ├── favicon.ico
│   └── firmware/
│       ├── projectA/
│       │   └── firmware_v1.bin
│       └── projectB/
│           ├── firmware_v1.bin
│           └── firmware_v2.bin
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

* he admin secret (X-Admin-Secret) must never be hardcoded.
It is read from the environment variable OTA_ADMIN_SECRET.
Set it securely before starting the server:

```bash
export OTA_ADMIN_SECRET="your-very-long-secret-value"
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