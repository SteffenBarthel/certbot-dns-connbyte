"""ConnByte DNS Authenticator plugin for Certbot.

The ``dns-connbyte`` plugin automates the DNS-01 challenge by creating, and
afterwards removing, TXT records with the ConnByte DNS API
(https://api.connbyte.com/). ConnByte: https://connbyte.com/

Credentials file (``chmod 600``)::

    dns_connbyte_api_token = 0123456789abcdef

Example::

    certbot certonly \\
      --authenticator dns-connbyte \\
      --dns-connbyte-credentials ~/.secrets/certbot/connbyte.ini \\
      -d example.com -d '*.example.com'
"""
