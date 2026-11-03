# Keycloak Breaking Change Impact Analyzer — POC

> «Devo aggiornare Keycloak dalla versione X alla Y. Quali dei miei 100 client sono impattati dalle breaking changes, quali funzionalità deprecated usano davvero e quali remediation devo applicare?»

Il POC chiude il ciclo **Breaking Change → Regola eseguibile → Test reale → Log ECS → Detection → Client impattato → Remediation** e lo presenta in una dashboard di *Upgrade Readiness*.

## Avvio rapido

```bash
cp .env.example .env
docker compose up -d --build          # Keycloak source/target, Postgres, Elasticsearch, Kibana, backend, frontend
open http://localhost:3000            # dashboard
```

| Servizio | URL |
|---|---|
| Dashboard (React) | http://localhost:3000 |
| API (FastAPI, OpenAPI su `/docs`) | http://localhost:8000 |
| keycloak-source 26.5.x | http://localhost:8080 (admin/admin) |
| keycloak-target 26.6.3 | http://localhost:8081 (admin/admin) |
| keycloak-legacy 25.0.6 (profilo `legacy`) | http://localhost:8082 |
| Elasticsearch / Kibana | http://localhost:9200 / http://localhost:5601 |

Con `AUTO_BOOTSTRAP=true` il backend all'avvio esegue le tre pipeline e gli assessment definiti in `data/scenarios/upgrade-scenarios.yaml`.

### Test

```bash
# unit + accuracy (offline, nessun container richiesto)
pip install -r backend/requirements.txt && pytest

# suite completa contro i container (traffico reale, evidenze in tests/.evidence/)
docker compose --profile tests run --rm test-runner

# prima/dopo per le BC introdotte in 26.0.0 e 26.4.3
docker compose --profile legacy up -d keycloak-legacy
KC_LEGACY_URL=http://keycloak-legacy:8080 docker compose --profile tests run --rm test-runner
```

### CLI

```bash
cd backend
STORE_BACKEND=memory python -m app.cli bootstrap          # tutto in memoria, utile per demo/debug
python -m app.cli assess 26.5.0 26.6.3 --origin keycloak-runtime
```

## Componenti

| Servizio | Funzione |
|---|---|
| `keycloak-source` / `keycloak-target` | versione pre/post upgrade, stesso realm `demo` (100 client fittizi) |
| `postgres-source` / `postgres-target` | database isolati |
| `elasticsearch` | 5 indici: knowledge, rules, realm snapshots, runtime logs, findings |
| `kibana` | ispezione indici |
| `backend` | FastAPI: ingestione, detection, RAG |
| `frontend` | dashboard React |
| `test-runner` | pytest: traffico OIDC reale + validation suite |

## Pipeline
- **A, Breaking changes** (`backend/app/ingestion/breaking_changes.py`): parsing della guida, chunk + embeddings locali, regole dal manifest validate contro il testo; LLM locale opzionale (`LLM_PROVIDER=ollama`) solo per *proporre* regole `candidate`.
- **B, Realm** (`ingestion/realms.py`): deterministica.
- **C, Log** (`ingestion/logs.py`): deterministica; `client_id = extracted_client_id or "anonymous"` + `client_identified`.

La detection esegue solo regole `approved` e non richiede un LLM.

## Breaking changes coperte

| ID | Cambiamento | Introdotta | Detection | Severità |
|---|---|---|---|---|
| KC-BC-001 | wildcard nell'host dei redirect URI | 26.6.3 | realm JSON + test OIDC | high |
| KC-BC-002 | `redirect_uri` sul logout | 26.0.0 | access log | critical |
| KC-BC-003 | path HTTP non normalizzati | 26.4.3 | access log + status | high |
| KC-BC-004 | role mapper non multivalore | 26.0.0 | realm JSON + token | high |
| KC-BC-005 | chiamate non attribuibili (controllo) | — | runtime log `anonymous` | info |

> ⚠️ La documentazione in `data/breaking-changes/` è un **estratto curato** che parafrasa la guida ufficiale, e la matrice dei test live deriva dal report tecnico: entrambe sono marcate come da verificare (`verified_against_official_docs`, `matrix_verified`).

## Dataset
`data/` è generato in modo deterministico da `scripts/generate_dataset.py` (seed fisso) ed è versionato. I log in `data/logs` sono **fixture sintetiche** (`labels.origin = synthetic-fixture`) e non vengono mai presentati come evidenza prodotta dal server; i log reali dei container hanno `labels.origin = keycloak-runtime`.

## Documentazione
- [Architettura](docs/architecture.md)
- [Valutazione e criteri di accettazione](docs/evaluation.md)
- [ADR](docs/adr/)

Tutti i dati (client, team, utenti, contatti) sono fittizi.
