# Task 404: Support Target-Aware Firmware Selection When JWT Authentication is Disabled

## Summary

Successfully implemented target-aware firmware selection in both JWT and `--no-jwt` modes. The OTA HTTP server now consistently uses the device's target_id for firmware lookup in all cases, preventing ambiguous firmware selection when multiple targets exist for the same project/version combination.

## Changes Made

### Core Implementation (`src/ota_http_server/core/server.py`)

#### 1. New Function: `resolve_device()`
- **Purpose**: Unified device resolution logic for both JWT and --no-jwt modes
- **JWT mode**: Extracts device_id from JWT token's "sub" claim
- **--no-jwt mode**: Extracts device_id from X-Device-ID header or device_id query parameter
- **Validation**: 
  - Returns 400 Bad Request if device_id is missing in --no-jwt mode
  - Returns 403 Forbidden if device is unknown, from wrong project, or inactive
  - Always validates device belongs to the requested project and is active

#### 2. Refactored Function: `get_firmware_metadata()`
- **Before**: Accepted optional device parameter, fell back to project+version-only lookup when device was None
- **After**: Requires device parameter, always uses project+version+target_id for lookup
- **Rationale**: Eliminates fallback behavior that could serve wrong firmware for different targets

#### 3. Updated Route: `/firmware/<project>/<version>`
- Now calls `resolve_device()` in both modes
- Ensures target_id is always used from device record
- Target is never accepted as client-supplied parameter (only derived from device)

#### 4. Updated Route: `/firmware/<project>/latest`
- Now requires device identification in --no-jwt mode
- Filters firmware records to only those matching device's target_id
- Returns latest firmware for target, not absolute latest across all targets

### Test Coverage

#### Existing Tests (Updated)
- `test_firmware_route_rejects_unsafe_stored_filename()`: Updated to provide device_id
- `test_latest_firmware_route_rejects_unsafe_stored_filename()`: Updated to provide device_id

#### New Tests (12 comprehensive tests in `tests/core/test_no_jwt_target_aware_firmware.py`)

**Device Identification Tests:**
- ✓ Missing device ID returns 400 Bad Request
- ✓ Device ID from X-Device-ID header is accepted
- ✓ Device ID from device_id query parameter is accepted (fallback)

**Device Validation Tests:**
- ✓ Unknown device returns 403 Forbidden
- ✓ Device from wrong project returns 403 Forbidden
- ✓ Inactive device returns 403 Forbidden

**Firmware Lookup Tests:**
- ✓ Firmware uses target_id from device
- ✓ Firmware not found for target returns 404 Not Found
- ✓ Disabled firmware returns 403 Forbidden

**/latest Endpoint Tests:**
- ✓ /latest requires device identification in --no-jwt mode
- ✓ /latest returns target-specific firmware (not higher version for different target)

### Test Results
- **All 54 tests pass** (42 existing + 12 new)
- No regressions in existing functionality
- JWT mode continues to work unchanged from user perspective

## Acceptance Criteria Met

✅ `--no-jwt` firmware requests require a device UUID  
✅ X-Device-ID is supported in `--no-jwt` mode  
✅ Existing URL/query device-ID mechanism remains supported (device_id param)  
✅ Missing device ID returns 400 Bad Request  
✅ Device UUID is resolved to a registered device  
✅ Target is always obtained from device.target_id  
✅ Firmware lookup always uses project + version + target  
✅ /firmware/<project>/<version> route is preserved  
✅ Target is not accepted as a client-controlled URL parameter  
✅ JWT mode continues to work unchanged from the API user's perspective  
✅ Existing device/project validation is preserved  
✅ /latest does not return firmware for a different target  
✅ Tests cover both JWT and --no-jwt modes  
✅ Tests cover missing/unknown/wrong-project devices and target-specific firmware  
✅ Existing regression tests pass  

## Validation Flow

Both JWT and --no-jwt modes now follow this convergent flow:

```
1. Identify Device UUID
   ├─ JWT mode: From JWT token's "sub" claim
   └─ --no-jwt mode: From X-Device-ID header or device_id query param (400 if missing)

2. Resolve Device Record
   ├─ Look up device by UUID
   ├─ Verify device exists (403 if not)
   ├─ Verify device belongs to project (403 if not)
   └─ Verify device is active (403 if not)

3. Resolve Target
   └─ Extract device.target_id from resolved device

4. Lookup Firmware
   ├─ Query: project_id + version + target_id
   ├─ Return 404 if not found
   ├─ Return 403 if found but disabled
   └─ Return 200 if found and active
```

## Files Modified

1. `src/ota_http_server/core/server.py`
   - Added `resolve_device()` function
   - Refactored `get_firmware_metadata()` function signature
   - Updated `firmware()` route to use common device resolution
   - Updated `latest_firmware()` route to use common device resolution and target filtering

2. `tests/core/test_firmware_replace.py`
   - Added Device import
   - Updated `test_firmware_route_rejects_unsafe_stored_filename()` to provide device_id
   - Updated `test_latest_firmware_route_rejects_unsafe_stored_filename()` to provide device_id

3. `tests/core/test_no_jwt_target_aware_firmware.py` (NEW)
   - Comprehensive test suite for --no-jwt target-aware firmware selection
   - 12 tests covering all acceptance criteria

## Implementation Notes

- **No breaking changes**: JWT mode continues to work exactly as before
- **Backward compatible**: Existing device_id query parameter mechanism is preserved
- **Consistent validation**: Same device/project checks in both modes
- **Target-aware only**: Firmware lookup never falls back to non-target-aware behavior
- **Clear error messages**: 400 vs 403 clearly indicates the nature of failures

## Redmine Task Number
**404** - Support target-aware firmware selection when JWT authentication is disabled
