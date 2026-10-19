certbot-dns-connbyte
====================

[ConnByte](https://connbyte.com/) DNS Authenticator plugin for [Certbot](https://certbot.eff.org/).

The plugin solves the `dns-01` challenge by creating and removing TXT records
with the [ConnByte DNS API](https://api.connbyte.com/). Use it to get wildcard
certificates or certificates for hosts that are not reachable from the internet.

## Installation

```sh
pip install certbot-dns-connbyte
```

## Credentials

Create an API token in your [ConnByte](https://connbyte.com/) account and store it in an INI file:

```ini
# ~/.secrets/certbot/connbyte.ini
dns_connbyte_api_token = 0123456789abcdef
```

Protect the file: `chmod 600 ~/.secrets/certbot/connbyte.ini`. Certbot warns if other users can read it.

## Usage

```sh
certbot certonly \
  --authenticator dns-connbyte \
  --dns-connbyte-credentials ~/.secrets/certbot/connbyte.ini \
  -d example.com -d '*.example.com'
```

| Option | Description |
| --- | --- |
| `--dns-connbyte-credentials` | Path to the credentials INI file (required). |
| `--dns-connbyte-propagation-seconds` | Seconds to wait for DNS propagation before the ACME server checks the record (default: 30). |

## Development

```sh
pip install -e '.[test]'
pytest
```

## License

Apache License 2.0
