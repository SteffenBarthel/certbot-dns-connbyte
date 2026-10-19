"""Small client for the ConnByte DNS API (https://api.connbyte.com/)."""

from __future__ import annotations

from typing import Any

import requests

DEFAULT_BASE_URL = "https://api.connbyte.com"
DEFAULT_TIMEOUT = 30


class ConnByteError(Exception):
    """Raised when the ConnByte API returns an error."""


class ConnByteClient:
    """Minimal client for the ConnByte ``/ns`` endpoints used for DNS-01."""

    def __init__(self, api_token: str, base_url: str = DEFAULT_BASE_URL,
                 session: requests.Session | None = None, timeout: int = DEFAULT_TIMEOUT) -> None:
        if not api_token:
            raise ConnByteError("ConnByte API token is missing")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "User-Agent": "certbot-dns-connbyte",
        })

    def _call(self, path: str, payload: dict[str, Any]) -> Any:
        try:
            resp = self.session.post(self.base_url + path, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise ConnByteError(f"ConnByte API request {path} failed: {e}") from e
        try:
            body = resp.json()
        except ValueError as e:
            raise ConnByteError(f"ConnByte API {path}: HTTP {resp.status_code}, invalid JSON") from e

        status = body.get("status") or {}
        code = status.get("code", resp.status_code)
        if resp.status_code // 100 != 2 or int(code) // 100 != 2:
            fields = "; ".join(f"{k}: {v}" for f in body.get("field") or [] for k, v in f.items())
            msg = f"ConnByte API {path}: {code} {status.get('title', '')}: {status.get('message', '')}"
            if fields:
                msg += f" [{fields}]"
            if status.get("logId"):
                msg += f" (logId {status['logId']})"
            raise ConnByteError(msg)
        return body.get("data")

    def list_zones(self) -> list[dict[str, Any]]:
        """Return all zones of the account as ``{"id": ..., "zone": ...}`` dicts."""
        data = self._call("/ns/zone/list", {}) or []
        return [item["zone"] for item in data if "zone" in item]

    def find_zone(self, domain: str) -> tuple[str, str]:
        """Return ``(zone_id, zone_name)`` of the longest zone that contains ``domain``."""
        domain = domain.rstrip(".").lower()
        zones = {z["zone"].rstrip(".").lower(): z["id"] for z in self.list_zones()}
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in zones:
                return zones[candidate], candidate
        raise ConnByteError(f"No ConnByte zone found for {domain}. Is the domain in your account?")

    def list_records(self, zone_id: str) -> list[dict[str, Any]]:
        data = self._call("/ns/record/list", {"zoneId": zone_id}) or []
        return [item["record"] for item in data if "record" in item]

    def add_txt_record(self, zone_id: str, name: str, content: str, ttl: int) -> int:
        """Create a TXT record. ``name`` is relative to the zone. Returns the record ID."""
        data = self._call("/ns/record/create", {
            "zoneId": zone_id,
            "name": name,
            "type": "TXT",
            "content": content,
            "ttl": ttl,
            "priority": 0,
            "disabled": False,
        })
        return int(data["id"])

    def delete_txt_record(self, zone_id: str, fqdn: str, content: str) -> int:
        """Delete all TXT records with the given FQDN and content. Returns the number deleted."""
        fqdn = fqdn.rstrip(".").lower()
        deleted = 0
        for rec in self.list_records(zone_id):
            if rec.get("type") != "TXT" or str(rec.get("name", "")).rstrip(".").lower() != fqdn:
                continue
            if _unquote(str(rec.get("content", ""))) != content:
                continue
            self._call("/ns/record/delete", {"zoneId": zone_id, "recordId": rec["id"]})
            deleted += 1
        return deleted


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value
