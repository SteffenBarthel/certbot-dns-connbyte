import json
import os
from unittest import mock

import pytest
import requests_mock as rm
from certbot import errors

from certbot_dns_connbyte.client import ConnByteClient, ConnByteError
from certbot_dns_connbyte.dns_connbyte import Authenticator, _relative_name

API = "https://api.connbyte.com"


def ok(path, data):
    return {"status": {"code": 200, "title": "OK", "message": "Data were transferred.", "path": path}, "data": data}


ZONES = ok("/ns/zone/list", [
    {"zone": {"id": "01ZONEA", "projectId": "01P", "zone": "example.com"}},
    {"zone": {"id": "01ZONEB", "projectId": "01P", "zone": "sub.example.com"}},
])


@pytest.fixture
def api():
    with rm.Mocker() as m:
        m.post(API + "/ns/zone/list", json=ZONES)
        yield m


def test_find_zone_longest_match(api):
    c = ConnByteClient("secret")
    assert c.find_zone("_acme-challenge.www.example.com") == ("01ZONEA", "example.com")
    assert c.find_zone("_acme-challenge.a.sub.example.com.") == ("01ZONEB", "sub.example.com")
    with pytest.raises(ConnByteError):
        c.find_zone("_acme-challenge.example.org")
    assert api.request_history[0].headers["Authorization"] == "Bearer secret"


def test_add_txt_record_payload(api):
    api.post(API + "/ns/record/create", json=ok("/ns/record/create", {"id": 435, "record": "x"}))
    c = ConnByteClient("secret")
    assert c.add_txt_record("01ZONEA", "_acme-challenge.www", "v1", 120) == 435
    assert api.last_request.json() == {
        "zoneId": "01ZONEA", "name": "_acme-challenge.www", "type": "TXT",
        "content": "v1", "ttl": 120, "priority": 0, "disabled": False,
    }


def test_delete_only_matching_txt(api):
    api.post(API + "/ns/record/list", json=ok("/ns/record/list", [
        {"record": {"id": 1, "name": "_acme-challenge.www.example.com", "type": "TXT", "content": "\"v1\"", "ttl": 120}},
        {"record": {"id": 2, "name": "_acme-challenge.www.example.com", "type": "TXT", "content": "\"v2\"", "ttl": 120}},
        {"record": {"id": 3, "name": "www.example.com", "type": "TXT", "content": "v1", "ttl": 120}},
    ]))
    api.post(API + "/ns/record/delete", json=ok("/ns/record/delete", {}))
    c = ConnByteClient("secret")
    assert c.delete_txt_record("01ZONEA", "_acme-challenge.www.example.com", "v1") == 1
    deletes = [r.json() for r in api.request_history if r.path == "/ns/record/delete"]
    assert deletes == [{"zoneId": "01ZONEA", "recordId": 1}]


def test_api_error_message(api):
    api.post(API + "/ns/record/create", status_code=400, json={
        "status": {"code": 400, "title": "Bad Request", "message": "Transferred data are incorrect.", "logId": "01LOG"},
        "field": [{"ttl": "Value too small."}],
    })
    c = ConnByteClient("secret")
    with pytest.raises(ConnByteError) as e:
        c.add_txt_record("01ZONEA", "x", "v", 1)
    assert "ttl: Value too small." in str(e.value) and "01LOG" in str(e.value)


def test_empty_token():
    with pytest.raises(ConnByteError):
        ConnByteClient("")


@pytest.mark.parametrize("fqdn,zone,want", [
    ("_acme-challenge.www.example.com", "example.com", "_acme-challenge.www"),
    ("_acme-challenge.example.com.", "example.com", "_acme-challenge"),
    ("example.com", "example.com", ""),
])
def test_relative_name(fqdn, zone, want):
    assert _relative_name(fqdn, zone) == want


def make_authenticator(tmp_path, token="secret"):
    creds = tmp_path / "connbyte.ini"
    creds.write_text(f"dns_connbyte_api_token = {token}\n")
    os.chmod(creds, 0o600)
    config = mock.MagicMock(dns_connbyte_credentials=str(creds), dns_connbyte_propagation_seconds=0)
    auth = Authenticator(config, "dns-connbyte")
    auth._setup_credentials()
    return auth


def test_authenticator_perform_and_cleanup(api, tmp_path):
    api.post(API + "/ns/record/create", json=ok("/ns/record/create", {"id": 7, "record": "x"}))
    api.post(API + "/ns/record/list", json=ok("/ns/record/list", [
        {"record": {"id": 7, "name": "_acme-challenge.sub.example.com", "type": "TXT", "content": "\"tok\"", "ttl": 120}},
    ]))
    api.post(API + "/ns/record/delete", json=ok("/ns/record/delete", {}))

    auth = make_authenticator(tmp_path)
    auth._perform("sub.example.com", "_acme-challenge.sub.example.com", "tok")
    create = [r.json() for r in api.request_history if r.path == "/ns/record/create"][0]
    assert create["zoneId"] == "01ZONEB" and create["name"] == "_acme-challenge" and create["ttl"] == 120

    auth._cleanup("sub.example.com", "_acme-challenge.sub.example.com", "tok")
    deletes = [r.json() for r in api.request_history if r.path == "/ns/record/delete"]
    assert deletes == [{"zoneId": "01ZONEB", "recordId": 7}]


def test_authenticator_perform_error(api, tmp_path):
    api.post(API + "/ns/record/create", status_code=403, json={
        "status": {"code": 403, "title": "Forbidden", "message": "No access."}})
    auth = make_authenticator(tmp_path)
    with pytest.raises(errors.PluginError):
        auth._perform("example.com", "_acme-challenge.example.com", "tok")


def test_cleanup_error_is_not_fatal(api, tmp_path):
    api.post(API + "/ns/record/list", status_code=500, json={"status": {"code": 500, "title": "Error", "message": "x"}})
    auth = make_authenticator(tmp_path)
    auth._cleanup("example.com", "_acme-challenge.example.com", "tok")  # must not raise
