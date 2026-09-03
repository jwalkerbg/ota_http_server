"""Tests for the /api/v1/devices routes."""


def test_list_devices_empty(client):
    response = client.get("/api/v1/devices")

    assert response.status_code == 200
    assert response.get_json() == {"devices": []}


def test_create_device(client, project, db):
    response = client.post(
        "/api/v1/devices",
        json={
            "uuid": "device-uuid-1",
            "project_id": project.id,
            "model": "ESP32S3",
            "serial_number": "SN-100",
        },
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["uuid"] == "device-uuid-1"
    assert payload["project_id"] == project.id
    assert payload["model"] == "ESP32S3"
    assert payload["current_version"] == "0.0.0"
    assert payload["is_active"] is True

    default_target = db.target_get_by_name("Not defined")
    assert payload["target_id"] == default_target.id


def test_create_device_duplicate_uuid_conflict(client, device, project):
    response = client.post(
        "/api/v1/devices",
        json={"uuid": device.uuid, "project_id": project.id},
    )

    assert response.status_code == 409


def test_create_device_unknown_project(client):
    response = client.post(
        "/api/v1/devices",
        json={"uuid": "device-uuid-9", "project_id": 999},
    )

    assert response.status_code == 400


def test_create_device_unknown_target(client, project):
    response = client.post(
        "/api/v1/devices",
        json={"uuid": "device-uuid-9", "project_id": project.id, "target_id": 999},
    )

    assert response.status_code == 400


def test_get_device(client, device):
    response = client.get(f"/api/v1/devices/{device.id}")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["id"] == device.id
    assert payload["uuid"] == device.uuid
    assert payload["serial_number"] == "SN-1"


def test_get_device_not_found(client):
    response = client.get("/api/v1/devices/999")

    assert response.status_code == 404


def test_patch_device(client, device):
    response = client.patch(
        f"/api/v1/devices/{device.id}",
        json={"model": "ESP32C6", "current_version": "2.0.0"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["model"] == "ESP32C6"
    assert payload["current_version"] == "2.0.0"
    assert payload["uuid"] == device.uuid


def test_patch_device_no_fields(client, device):
    response = client.patch(f"/api/v1/devices/{device.id}", json={})

    assert response.status_code == 400


def test_patch_device_not_found(client):
    response = client.patch("/api/v1/devices/999", json={"model": "x"})

    assert response.status_code == 404


def test_patch_device_serial_number_conflict(client, make_device, project):
    make_device(uuid="uuid-a", project_id=project.id, serial_number="SN-TAKEN")
    other = make_device(uuid="uuid-b", project_id=project.id, serial_number="SN-FREE")

    response = client.patch(
        f"/api/v1/devices/{other.id}",
        json={"serial_number": "SN-TAKEN"},
    )

    assert response.status_code == 409


def test_patch_device_unknown_target(client, device):
    response = client.patch(f"/api/v1/devices/{device.id}", json={"target_id": 999})

    assert response.status_code == 400


def test_delete_device_deactivates(client, device, db):
    response = client.delete(f"/api/v1/devices/{device.id}")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is False
    assert db.device_get_by_id(device.id).is_active is False


def test_delete_device_twice_conflicts(client, device):
    assert client.delete(f"/api/v1/devices/{device.id}").status_code == 200

    response = client.delete(f"/api/v1/devices/{device.id}")

    assert response.status_code == 409


def test_activate_device(client, device, db):
    db.device_disable_by_id(device.id)

    response = client.post(f"/api/v1/devices/{device.id}/activate")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is True
    assert db.device_get_by_id(device.id).is_active is True


def test_deactivate_device_not_found(client):
    response = client.post("/api/v1/devices/999/deactivate")

    assert response.status_code == 404


def test_list_devices_filters(client, make_user, make_project, make_device):
    owner = make_user(username="owner")
    first = make_project(name="first", created_by=owner.id)
    second = make_project(name="second", created_by=owner.id)
    make_device(uuid="d1", project_id=first.id)
    make_device(uuid="d2", project_id=first.id, is_active=False)
    make_device(uuid="d3", project_id=second.id)

    response = client.get(f"/api/v1/devices?projectid={first.id}")
    assert {d["uuid"] for d in response.get_json()["devices"]} == {"d1", "d2"}

    response = client.get("/api/v1/devices?state=disabled")
    assert {d["uuid"] for d in response.get_json()["devices"]} == {"d2"}

    response = client.get(f"/api/v1/devices?projectid={first.id}&state=enabled")
    assert {d["uuid"] for d in response.get_json()["devices"]} == {"d1"}

    response = client.get("/api/v1/devices")
    assert len(response.get_json()["devices"]) == 3

    # list items expose the project and target names
    item = response.get_json()["devices"][0]
    assert "project" in item
    assert "target" in item


def test_list_devices_invalid_projectid(client):
    response = client.get("/api/v1/devices?projectid=abc")

    assert response.status_code == 400
