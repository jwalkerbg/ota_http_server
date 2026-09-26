# Release Notes - Version 3.3.0

**Release Date:** 2026-08-31  
**Redmine Task:** #405

## Overview

Version 3.3.0 introduces comprehensive MySQL support, target-aware firmware selection, enhanced logging capabilities, and improved CLI functionality. This release significantly expands the platform's flexibility and operational visibility.

---

## Major Features

### 1. MySQL Database Support (RT #386)

Full MySQL database layer implementation providing an alternative to SQLite for production deployments.

**Changes:**
- Implemented complete MySQL CRUD layer with optimized query patterns
- Added MySQL migration runner and schema scripts
- Created MySQL configuration schema with database name specification
- Supports all core entities: users, projects, devices, firmware, and targets
- Full feature parity with existing SQLite implementation

**Benefits:**
- Better scalability for large-scale deployments
- Native support for enterprise database environments
- Improved performance for high-volume operations

---

### 2. Target-Aware Firmware Selection (RT #399, RT #404)

New data model and selection logic enabling firmware to be associated with specific device targets.

**Changes:**
- Added target data model with comprehensive CLI management (RT #398)
- Implemented target-aware OTA firmware selection logic
- Extended firmware selection to work in `--no-jwt` mode with target awareness
- Created database migration for targets table with proper foreign key relationships

**Benefits:**
- More granular control over firmware updates per device target
- Support for multi-target environments
- Flexible firmware management without JWT authentication

---

### 3. Enhanced Admin Activity Logging (RT #392)

New admin activity logging system with generic rotation capabilities.

**Changes:**
- Created dedicated `admin_activity_logger` module
- Implemented generic log rotation with configurable retention policies
- Tracks administrative actions with detailed audit trail
- Integrated with HTTP token audit logging (RT #395)

**File Changes:**
- New: `src/ota_http_server/logger/admin_activity_logger.py`
- New: `tests/core/test_admin_activity_logging.py`
- New: `tests/core/test_server_admin_token_activity_logging.py`

---

### 4. OTA Download Request Logging (RT #397)

New logging capability for OTA download requests providing detailed operational insights.

**Changes:**
- Captures OTA download requests with comprehensive metadata
- Added dedicated test coverage
- Integrated with existing logging infrastructure

**File Changes:**
- New: `tests/core/test_server_ota_download_logging.py`

---

### 5. Log Rotation Improvements (RT #396)

Enhanced log file naming convention for better date tracking.

**Changes:**
- Renamed rotated logs to place date before file extension
- Example: `app.log` rotates to `app-2026-08-31.log` format
- Improved log file organization and discoverability

---

### 6. Firmware Management Enhancements

#### Firmware Delete Command (RT #390)
- Added new `firmware delete` CLI command
- Implements single-operation database delete for atomicity
- Comprehensive test coverage

#### Audit Logging Refactor (RT #395)
- Removed obsolete OTA audit configuration options
- Aligned HTTP token audit logging with new admin activity logger
- Cleaner, more maintainable audit trail configuration

**File Changes:**
- New: `tests/core/test_firmware_replace.py` (expanded coverage)

---

## Improvements & Fixes

### CLI Enhancements

**RT #391:** Fixed `-v` (version) option dependency issue
- Previously required `--dbtype` and command parameters
- Now `--dbtype` and command are optional when using `-v`
- Better user experience for simple info queries

**RT #393:** Corrected log levels for database listings
- Improved logging granularity for database operations

### MySQL SQL Tracing (RT #400)

- Restored SQL statement tracing for MySQL deployments
- Helps with debugging and performance analysis
- Module: `src/ota_http_server/database/mysql_sql_tracing.py`

**File Changes:**
- New: `tests/core/test_mysql_sql_tracing.py`

---

## Dependencies

- Added `colorama` dependency for enhanced CLI output formatting
- Updated poetry dependencies (run `poetry update` or `poetry install`)

**Modified Files:**
- `pyproject.toml`: Dependency additions
- `poetry.lock`: Dependency resolution

---

## Configuration Changes

### MySQL Configuration

New configuration schema for MySQL database selection:

```toml
[database]
type = "mysql"

[database.mysql]
host = "localhost"
port = 3306
user = "ota_user"
password = "secure_password"
database = "ota_http_server"  # Database name (required)
```

**File Changes:**
- Enhanced: `src/ota_http_server/core/config.py` (189 lines added/modified)
- Updated: `config.toml` with MySQL examples

---

## Testing

New comprehensive test suites added:

| Test Suite | Coverage |
|---|---|
| `test_admin_activity_logging.py` | Admin activity logging functionality |
| `test_target_support.py` | Target data model and operations |
| `test_target_migrations.py` | Target schema migrations |
| `test_no_jwt_target_aware_firmware.py` | Target-aware firmware in no-JWT mode |
| `test_mysql_sql_tracing.py` | MySQL SQL tracing |
| `test_server_ota_download_logging.py` | OTA download request logging |
| `test_server_admin_token_activity_logging.py` | Admin token activity logging |

---

## Code Changes Summary

**Total Changes:**
- **Files Modified:** 44
- **Lines Added:** ~5,700
- **Lines Removed:** ~576
- **Net Change:** +5,124 lines

**Major Components Updated:**
1. Database layer (MySQL support, migrations, schema)
2. Server core (configuration, logging, target support)
3. Firmware service (target-aware selection, delete operations)
4. Device service (target integration)
5. Logging infrastructure (admin activity, audit trails)

---

## Migration Guide

### For Existing SQLite Deployments

No action required. SQLite remains fully supported and is the default option.

### Migrating to MySQL

1. Ensure MySQL server is running and accessible
2. Update `config.toml` with MySQL connection details
3. Ensure the target database exists (schema will be created automatically)
4. Start the application - migrations run on startup
5. Verify database connectivity in application logs

### New Features Adoption

- **Target Management:** Use new CLI commands to create and manage device targets
- **Admin Logging:** Activity logs automatically captured in configured location
- **Firmware Delete:** New CLI command available for firmware management

---

## Deprecated Features

- Obsolete OTA audit configuration options removed (RT #395)
- Recommend using new admin activity logger for audit trails

---

## Known Issues

None at this time.

---

## Contributors

- imc (lead developer)
- Ivan Cenov (release coordination)

---

## Version History

- **3.3.0** - Current Release
- **3.2.0** - Previous Release

For detailed commit history, see: `git log 3.2.0..3.3.0`
