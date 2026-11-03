# Keycloak containers

All Keycloak services share the same configuration principles:

| Setting | Value | Why |
|---|---|---|
| `KC_LOG=console,file` + `KC_LOG_FILE_OUTPUT=json` + `KC_LOG_*_JSON_FORMAT=ecs` | ECS JSON logs | Pipeline C reads `/opt/keycloak/data/log/keycloak.log` from a shared volume |
| `KC_HTTP_ACCESS_LOG_ENABLED=true`, pattern `combined` | HTTP access log | Runtime detection of endpoints, parameters and status codes |
| `KC_LOG_MDC_ENABLED=true`, keys `realmName,clientId,userId,ipAddress` | MDC | Attribution of log records to a client (`kc.clientId`) |
| realm `demo` imported from `data/realms/enterprise-realm.json` | 100 fictitious clients | Same configuration on every version |
| events listener `jboss-logging` (realm setting) | `org.keycloak.events` records | Events with `clientId` |

`healthcheck.sh` probes `/health/ready` on the management port (9000) using bash only,
because the official image does not contain curl.

The `legacy` compose profile starts Keycloak 25.0.6 with
`KC_SPI_LOGIN_PROTOCOL_OPENID_CONNECT_LEGACY_LOGOUT_REDIRECT_URI=true`, required to
observe the before/after of the breaking changes introduced in 26.0.0 and 26.4.3.
Options that a given version does not know are ignored by Keycloak; verify the
exact option names against the documentation of the version you run.
