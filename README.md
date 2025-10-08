# OTA Firmware Server

A lightweight Python/Flask-based firmware server for Over-The-Air (OTA) updates.
Supports **token-based authentication** and can run in two modes:

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
pip install flask
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
python http_server.py --no-certs --token mytoken --port 8070
```
8. Access firmware:
```bash
http://localhost:8070/firmware/projectA/firmware_v1.bin?token=mytoken
```

## Features

* Serve firmware files from a defined directory structure
* Optional token authentication (Authorization: Bearer <token> or ?token=<token>)
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
    --token mytoken \
    --host 0.0.0.0 \
    --port 8070 \
    --www-dir www \
    --firmware-dir firmware \
    --url-firmware firmware
```

### Start without SSL (for Apache reverse proxy)

```bash
python http_server.py --no-certs --token mytoken --port 8071
```

See the virtual host and reverse proxy configurations to figure out ports usage.

If `--no-token` option is given the token is not used event it is supplied at the end of the url.

## Apache Reverse Proxy Mode

### Running multiple http_server.py

You can place multiple instances of ```http_server.py``` behind Apache for load balancing.

```bash
python http_server.py --no-certs --token mytoken --port 8071
python http_server.py --no-certs --token mytoken --port 8072
python http_server.py --no-certs --token mytoken --port 8073
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

Token authentication is enabled by default. Clients can pass the token as URL parameter.

```
GET /firmware/projectA/firmware_v1.bin?token=mytoken
```

## Favicon

The server automatically serves ```/favicon.ico``` from the ```www/``` directory if present.
Browsers usually cache this file, so it will only be requested once. Devices initiating OTA do not request ```favicon.ico```.

### Example OTA Firmware URL

With token
```bash
https://mycompany.com/firmware/projectA/firmware_v1.bin?token=mytoken
```

Without token
```bash
https://mycompany.com/firmware/projectA/firmware_v1.bin
```