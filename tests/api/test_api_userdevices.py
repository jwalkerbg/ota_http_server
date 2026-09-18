"""Tests for the /api/v1/userdevices routes."""


def test_create_user_device_by_id(client, user, device, db):
    response = client.post(
        "/api/v1/userdevices",
        json={"user_id": user.id, "device_id": device.id},
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["user_id"] == user.id
    assert payload["device_id"] == device.id
    assert payload["expires_at"] is None

    assert db.user_device_get(user.id, device.id) is not None


def test_create_user_device_by_username_and_uuid(client, user, device):
    response = client.post(
        "/api/v1/userdevices",
        json={
            "username": user.username,
            "device_uuid": device.uuid,
            "expires_at": "2026-09-18T12:30:00+00:00",
        },
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["user_id"] == user.id
    assert payload["device_id"] == device.id
    assert payload["expires_at"] == "2026-09-18T12:30:00+00:00"


def test_create_user_device_requires_exactly_one_user_identifier(client, user, device):
    response = client.post(
        "/api/v1/userdevices",
        json={"user_id": user.id, "username": user.username, "device_id": device.id},
    )

    assert response.status_code == 400


def test_create_user_device_requires_exactly_one_device_identifier(client, user, device):
    response = client.post(
        "/api/v1/userdevices",
        json={"user_id": user.id},
    )

    assert response.status_code == 400


def test_create_user_device_unknown_user(client, device):
    response = client.post(
        "/api/v1/userdevices",
        json={"user_id": 999, "device_id": device.id},
    )

    assert response.status_code == 404


def test_create_user_device_unknown_device(client, user):
    response = client.post(
        "/api/v1/userdevices",
        json={"user_id": user.id, "device_id": 999},
    )

    assert response.status_code == 404


def test_create_user_device_duplicate_conflict(client, user, device):
    client.post("/api/v1/userdevices", json={"user_id": user.id, "device_id": device.id})

    response = client.post(
        "/api/v1/userdevices",
        json={"user_id": user.id, "device_id": device.id},
    )

    assert response.status_code == 409


def test_get_user_device(client, user, device):
    client.post("/api/v1/userdevices", json={"user_id": user.id, "device_id": device.id})

    response = client.get(f"/api/v1/userdevices?userid={user.id}&devid={device.id}")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["user_id"] == user.id
    assert payload["device_id"] == device.id


def test_get_user_device_by_username_and_uuid(client, user, device):
    client.post("/api/v1/userdevices", json={"user_id": user.id, "device_id": device.id})

    response = client.get(
        f"/api/v1/userdevices?username={user.username}&devuuid={device.uuid}"
    )

    assert response.status_code == 200


def test_get_user_device_not_found(client, user, device):
    response = client.get(f"/api/v1/userdevices?userid={user.id}&devid={device.id}")

    assert response.status_code == 404


def test_get_user_device_expiration(client, user, device):
    client.post(
        "/api/v1/userdevices",
        json={
            "user_id": user.id,
            "device_id": device.id,
            "expires_at": "2000-01-01T00:00:00+00:00",
        },
    )

    response = client.get(f"/api/v1/userdevices/expiration?userid={user.id}&devid={device.id}")

    assert response.status_code == 200
    assert response.get_json()["expired"] is True


def test_get_user_device_expiration_not_found(client, user, device):
    response = client.get(f"/api/v1/userdevices/expiration?userid={user.id}&devid={device.id}")

    assert response.status_code == 404


def test_set_user_device_expiry(client, user, device, db):
    client.post("/api/v1/userdevices", json={"user_id": user.id, "device_id": device.id})

    response = client.patch(
        f"/api/v1/userdevices?userid={user.id}&devid={device.id}",
        json={"expires_at": "2026-09-18T12:30:00+00:00"},
    )

    assert response.status_code == 200
    assert response.get_json()["expires_at"] == "2026-09-18T12:30:00+00:00"
    assert db.user_device_get(user.id, device.id).expires_at is not None


def test_set_user_device_expiry_removes_expiry_when_omitted(client, user, device, db):
    client.post(
        "/api/v1/userdevices",
        json={
            "user_id": user.id,
            "device_id": device.id,
            "expires_at": "2026-09-18T12:30:00+00:00",
        },
    )

    response = client.patch(
        f"/api/v1/userdevices?userid={user.id}&devid={device.id}",
        json={},
    )

    assert response.status_code == 200
    assert response.get_json()["expires_at"] is None
    assert db.user_device_get(user.id, device.id).expires_at is None


def test_set_user_device_expiry_not_found(client, user, device):
    response = client.patch(
        f"/api/v1/userdevices?userid={user.id}&devid={device.id}",
        json={},
    )

    assert response.status_code == 404


def test_delete_user_device(client, user, device, db):
    client.post("/api/v1/userdevices", json={"user_id": user.id, "device_id": device.id})

    response = client.delete(f"/api/v1/userdevices?userid={user.id}&devid={device.id}")

    assert response.status_code == 200
    assert db.user_device_get(user.id, device.id) is None


def test_delete_user_device_not_found(client, user, device):
    response = client.delete(f"/api/v1/userdevices?userid={user.id}&devid={device.id}")

    assert response.status_code == 404


def test_userdevices_require_identification(client):
    response = client.get("/api/v1/userdevices")

    assert response.status_code == 400
