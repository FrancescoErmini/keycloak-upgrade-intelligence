# ADR 0004 — Client non identificato

**Stato:** accettato · **Data:** 2026-11-04

`client_id = extracted_client_id or "anonymous"`, con `client_identified: false`.

Ordine di estrazione: MDC `kc.clientId` → `clientId` dell'evento → parametro `client_id` della query → `anonymous`.

`client_identified: false` **non** significa chiamante non autenticato: significa solo che il record non è attribuibile a un client Keycloak.

In fase di analisi (non di ingestione) un hit anonimo può essere attribuito per inferenza quando il valore di `redirect_uri` corrisponde ai redirect URI registrati di **un solo** client (`attribution: inferred-redirect-uri`, confidenza ×0.85). Il record di log resta `anonymous`.
