"""DNS Authenticator for ConnByte."""

from __future__ import annotations

import logging
from typing import Any, Callable

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

from certbot_dns_connbyte.client import ConnByteClient, ConnByteError

logger = logging.getLogger(__name__)

TOKEN_URL = "https://connbyte.com/"
MIN_TTL = 60
DEFAULT_TTL = 120


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for ConnByte.

    This Authenticator uses the ConnByte DNS API to fulfill a dns-01 challenge.
    """

    description = ("Obtain certificates using a DNS TXT record "
                   "(if you are using ConnByte for DNS).")
    ttl = DEFAULT_TTL

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: CredentialsConfiguration | None = None
        self._client: ConnByteClient | None = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="ConnByte credentials INI file.")

    def more_info(self) -> str:
        return ("This plugin configures a DNS TXT record to respond to a dns-01 challenge "
                "using the ConnByte DNS API (https://connbyte.com/).")

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "ConnByte credentials INI file",
            {"api-token": f"API token for the ConnByte DNS API, see {TOKEN_URL}"},
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        try:
            zone_id, zone = client.find_zone(validation_name)
            name = _relative_name(validation_name, zone)
            client.add_txt_record(zone_id, name, validation, max(self.ttl, MIN_TTL))
        except ConnByteError as e:
            raise errors.PluginError(f"Error adding TXT record for {validation_name}: {e}") from e

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        try:
            zone_id, _ = client.find_zone(validation_name)
            client.delete_txt_record(zone_id, validation_name, validation)
        except ConnByteError as e:
            logger.warning("Error removing TXT record for %s: %s", validation_name, e)

    def _get_client(self) -> ConnByteClient:
        if self._client is None:
            if not self.credentials:  # pragma: no cover
                raise errors.Error("Plugin has not been prepared.")
            token = self.credentials.conf("api-token")
            base_url = self.credentials.conf("base-url") or "https://api.connbyte.com"
            try:
                self._client = ConnByteClient(token, base_url=base_url)
            except ConnByteError as e:
                raise errors.PluginError(str(e)) from e
        return self._client


def _relative_name(fqdn: str, zone: str) -> str:
    fqdn = fqdn.rstrip(".").lower()
    zone = zone.rstrip(".").lower()
    if fqdn == zone:
        return ""
    return fqdn[: -(len(zone) + 1)]
