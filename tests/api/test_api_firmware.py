"""Tests for the /api/v1/firmware routes."""

import hashlib
import io


def test_list_firmware_empty(client):
    response = client.get("/api/v1/firmware")

    assert response.status_code == 200
    assert response.get_json() == {"firmware": []}


def _upload(client, project_id, version="1.2.3", filename="fw.bin", content=b"image-bytes", **fields):
    data = {
        "project_id": str(project_id),
        "version": version,
        "file": (io.BytesIO(content), filename),
    }
    data.update(fields)
    return client.post(
        "/api/v1/firmware",
        data=data,
        content_type="multipart/form-data",
    )


def test_upload_firmware(client, project, app):
    response = _upload(client, project.id, release_notes="first", channel="beta")

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["project_id"] == project.id
    assert payload["version"] == "1.2.3"
    assert payload["filename"] == "fw.bin"
    assert payload["file_size"] == len(b"image-bytes")
    assert payload["checksum"] == hashlib.sha256(b"image-bytes").hexdigest()
    assert payload["channel"] == "beta"
    assert payload["release_notes"] == "first"
    assert payload["is_active"] is True

    app_paths = app.extensions["app_paths"]
    stored = app_paths.project_dir(project.name) / "fw.bin"
    assert stored.read_bytes() == b"image-bytes"


def test_upload_firmware_duplicate_conflict(client, project):
    assert _upload(client, project.id).status_code == 201

    response = _upload(client, project.id)

    assert response.status_code == 409


def test_upload_firmware_missing_file(client, project):
    response = client.post(
        "/api/v1/firmware",
        data={"project_id": str(project.id), "version": "1.0.0"},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_upload_firmware_missing_version(client, project):
    response = client.post(
        "/api/v1/firmware",
        data={
            "project_id": str(project.id),
            "file": (io.BytesIO(b"x"), "fw.bin"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_upload_firmware_unknown_project(client):
    response = _upload(client, 999)

    assert response.status_code == 400


def test_upload_firmware_invalid_channel(client, project):
    response = _upload(client, project.id, channel="nightly")

    assert response.status_code == 400


def test_upload_firmware_unsafe_filename(client, project):
    response = _upload(client, project.id, filename="../evil.bin")

    assert response.status_code == 400


def test_get_firmware(client, firmware):
    response = client.get(f"/api/v1/firmware/{firmware.id}")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["id"] == firmware.id
    assert payload["version"] == firmware.version
    assert payload["checksum"] == firmware.checksum


def test_get_firmware_not_found(client):
    response = client.get("/api/v1/firmware/999")

    assert response.status_code == 404


def test_patch_firmware(client, firmware, db):
    response = client.patch(
        f"/api/v1/firmware/{firmware.id}",
        json={"release_notes": "updated notes", "channel": "dev"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["release_notes"] == "updated notes"
    assert payload["channel"] == "dev"
    assert payload["version"] == firmware.version


def test_patch_firmware_no_fields(client, firmware):
    response = client.patch(f"/api/v1/firmware/{firmware.id}", json={})

    assert response.status_code == 400


def test_patch_firmware_invalid_channel(client, firmware):
    response = client.patch(f"/api/v1/firmware/{firmware.id}", json={"channel": "nightly"})

    assert response.status_code == 400


def test_patch_firmware_not_found(client):
    response = client.patch("/api/v1/firmware/999", json={"version": "9.9.9"})

    assert response.status_code == 404


def test_patch_firmware_version_conflict(client, make_firmware, project):
    first = make_firmware(project, version="1.0.0")
    make_firmware(project, version="2.0.0")

    response = client.patch(f"/api/v1/firmware/{first.id}", json={"version": "2.0.0"})

    assert response.status_code == 409


def test_delete_firmware(client, firmware, db, app, project):
    app_paths = app.extensions["app_paths"]
    stored = app_paths.project_dir(project.name) / firmware.filename
    assert stored.exists()

    response = client.delete(f"/api/v1/firmware/{firmware.id}")

    assert response.status_code == 200
    assert db.firmware_get_by_id(firmware.id) is None
    assert not stored.exists()


def test_delete_firmware_not_found(client):
    response = client.delete("/api/v1/firmware/999")

    assert response.status_code == 404


def test_download_firmware(client, firmware):
    response = client.get(f"/api/v1/firmware/{firmware.id}/download")

    assert response.status_code == 200
    assert response.data == b"firmware-image"
    assert "attachment" in response.headers["Content-Disposition"]
    assert firmware.filename in response.headers["Content-Disposition"]


def test_download_firmware_not_found(client):
    response = client.get("/api/v1/firmware/999/download")

    assert response.status_code == 404


def test_download_firmware_missing_file(client, firmware, app, project):
    app_paths = app.extensions["app_paths"]
    stored = app_paths.project_dir(project.name) / firmware.filename
    stored.unlink()

    response = client.get(f"/api/v1/firmware/{firmware.id}/download")

    assert response.status_code == 404


def test_list_firmware_filters(client, make_user, make_project, make_firmware):
    owner = make_user(username="owner")
    first = make_project(name="first", created_by=owner.id)
    second = make_project(name="second", created_by=owner.id)
    make_firmware(first, version="1.0.0")
    make_firmware(first, version="1.1.0", is_active=False)
    make_firmware(second, version="3.0.0")

    response = client.get(f"/api/v1/firmware?projectid={first.id}")
    assert {f["version"] for f in response.get_json()["firmware"]} == {"1.0.0", "1.1.0"}

    response = client.get("/api/v1/firmware?state=disabled")
    assert {f["version"] for f in response.get_json()["firmware"]} == {"1.1.0"}

    response = client.get(f"/api/v1/firmware?projectid={first.id}&state=enabled")
    assert {f["version"] for f in response.get_json()["firmware"]} == {"1.0.0"}

    response = client.get("/api/v1/firmware")
    items = response.get_json()["firmware"]
    assert len(items) == 3
    assert all("is_active" in item for item in items)


def test_list_firmware_invalid_projectid(client):
    response = client.get("/api/v1/firmware?projectid=abc")

    assert response.status_code == 400
