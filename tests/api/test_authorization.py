"""Tests for centralized REST API authorization."""

from ota_http_server.api.authorization import PERMISSIONS, ROLE_PERMISSIONS, has_permission


def test_viewer_can_read_but_cannot_write(client, set_api_role):
    set_api_role("viewer")

    assert client.get("/api/v1/status").status_code == 200
    assert client.get("/api/v1/projects").status_code == 200
    assert client.get("/api/v1/devices").status_code == 200
    assert client.get("/api/v1/firmware").status_code == 200
    assert client.post("/api/v1/projects", json={}).status_code == 403
    assert client.post("/api/v1/devices", json={}).status_code == 403
    assert client.post("/api/v1/firmware").status_code == 403


def test_operator_can_manage_assigned_resources_but_not_delete(client, set_api_role, user):
    set_api_role("operator")

    response = client.post("/api/v1/projects", json={"name": "operator-project", "created_by": user.id})

    assert response.status_code == 201
    assert client.delete("/api/v1/projects/999").status_code == 403
    assert client.get("/api/v1/users").status_code == 403


def test_admin_has_every_defined_permission(client, set_api_role):
    set_api_role("admin")

    assert ROLE_PERMISSIONS["admin"] == PERMISSIONS
    assert all(has_permission("admin", permission) for permission in PERMISSIONS)
    assert client.get("/api/v1/users").status_code == 200


def test_unknown_permission_or_role_is_denied_safely():
    assert not has_permission("admin", "unsupported.permission")
    assert not has_permission("unsupported-role", "projects.read")


def test_every_rest_endpoint_declares_a_permission(app):
    api_rules = [rule for rule in app.url_map.iter_rules() if rule.rule.startswith("/api/v1")]

    assert api_rules
    for rule in api_rules:
        view = app.view_functions[rule.endpoint]
        assert getattr(view, "required_permission", None), rule.rule
