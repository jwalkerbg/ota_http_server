import sys

import pytest

from ota_http_server.core.config import parse_args


@pytest.mark.parametrize(
    "argv, attr, value",
    [
        (["user", "delete", "--user-id", "3"], "user_id", 3),
        (["user", "delete", "--username", "bob"], "username", "bob"),
        (["project", "delete", "--id", "3"], "project_id", 3),
        (["project", "delete", "--name", "p"], "project_name", "p"),
        (["device", "delete", "--id", "3"], "device_id", 3),
        (["device", "delete", "--uuid", "u"], "device_uuid", "u"),
    ],
)
def test_delete_accepts_single_selector(monkeypatch, argv, attr, value):
    monkeypatch.setattr(sys, "argv", ["ota_http_server", *argv])

    assert getattr(parse_args(), attr) == value


@pytest.mark.parametrize(
    "argv",
    [
        ["user", "delete", "--user-id", "1", "--username", "bob"],
        ["project", "delete", "--id", "1", "--name", "p"],
        ["device", "delete", "--id", "1", "--uuid", "u"],
        ["user", "delete"],
        ["project", "delete"],
        ["device", "delete"],
    ],
)
def test_delete_rejects_both_or_no_selector(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["ota_http_server", *argv])

    with pytest.raises(SystemExit):
        parse_args()
