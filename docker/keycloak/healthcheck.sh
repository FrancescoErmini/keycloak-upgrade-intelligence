#!/bin/bash
# The Keycloak image ships without curl: query the management port with bash /dev/tcp.
exec 3<>/dev/tcp/127.0.0.1/9000 || exit 1
printf 'GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
grep -q '"status": *"UP"' <&3
