# ADR 0001 — Ambiente Docker Compose con due versioni di Keycloak

**Stato:** accettato · **Data:** 2026-11-04

## Contesto
Per dimostrare una breaking change serve osservare lo stesso comportamento prima e dopo l'upgrade, sulla stessa configurazione.

## Decisione
- `keycloak-source` (26.5.x) e `keycloak-target` (26.6.3+), ciascuno con il proprio Postgres, importano lo stesso realm `demo`.
- Profilo opzionale `legacy` (25.0.6, con `legacy-logout-redirect-uri` abilitato) per le BC introdotte in 26.0.0 e 26.4.3, che non cambiano comportamento tra 26.5 e 26.6.3.
- Log ECS JSON su file in volumi dedicati, letti in sola lettura dal backend.

## Conseguenze
Avvio riproducibile con un solo comando; i database separati evitano che i test su una versione alterino lo stato dell'altra. Le opzioni di logging (`log-mdc-*`, `http-access-log-*`) vanno verificate sulla versione effettiva.
