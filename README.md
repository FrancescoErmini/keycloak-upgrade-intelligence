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
- **Sync manuale della guida ufficiale** (`backend/app/jobs/sync_breaking_changes.py`): scarica la pagina, la serializza in `data/breaking-changes/catalog.json` (indice versioni *da → a*, categorie breaking / notable / deprecated / removed / end-of-life, voci), e usa OpenAI per ricavare da ogni voce le **verifiche** da fare su un'istanza reale (più check per voce, ognuno con la sua fonte dati: realm export, access log, event log, server log, server config, server info, SPI…). I check che corrispondono a un detector del registro diventano eseguibili; in detection girano solo quelli con fonte disponibile (`AVAILABLE_DATA_SOURCES`). Vedi [docs/breaking-changes-sync.md](docs/breaking-changes-sync.md).
- **A, Breaking changes** (`backend/app/ingestion/breaking_changes.py`): indicizza catalogo + regole approvate/candidate; nessuna rete, nessun LLM.
- **B, Realm** (`ingestion/realms.py`): deterministica.
- **C, Log** (`ingestion/logs.py`): deterministica; `client_id = extracted_client_id or "anonymous"` + `client_identified`.

La detection esegue solo regole `approved` e non richiede un LLM.

## Breaking changes coperte

| ID | Cambiamento | Introdotta | Detection | Severità |
|---|---|---|---|---|
| KC-BC-001 | wildcard nell'host dei redirect URI | 26.6.3 | realm JSON + test OIDC | high |
| KC-BC-002 | `redirect_uri` sul logout | 26.0.0 | access log | critical |
| KC-BC-003 | path HTTP non normalizzati | 26.4.3 | access log + status | high |
| KC-BC-004 | role mapper single-valued: ora emettono un singolo valore | 23.0.0 | realm JSON + token | high |
| KC-BC-005 | chiamate non attribuibili (controllo) | — | runtime log `anonymous` | info |

Le quattro regole approvate (`data/breaking-changes/rules/approved-rules.json`) citano verbatim le voci della guida ufficiale; tutte le altre voci della guida sono indicizzate per il RAG e, dopo il sync con LLM, diventano regole `candidate` da revisionare.

### Sync della guida (job manuale)

```bash
echo "OPENAI_API_KEY=sk-..." >> .env
docker compose --profile jobs run --rm bc-sync              # download → JSON → LLM → indice
docker compose --profile jobs run --rm bc-sync --dry-run    # solo download + parse + diff
```

## Dataset
`data/` è generato in modo deterministico da `scripts/generate_dataset.py` (seed fisso) ed è versionato. I log in `data/logs` sono **fixture sintetiche** (`labels.origin = synthetic-fixture`) e non vengono mai presentati come evidenza prodotta dal server; i log reali dei container hanno `labels.origin = keycloak-runtime`.

## Documentazione
- [Architettura](docs/architecture.md)
- [Valutazione e criteri di accettazione](docs/evaluation.md)
- [Sync delle breaking changes e coerenza delle label LLM](docs/breaking-changes-sync.md)
- [ADR](docs/adr/)

Tutti i dati (client, team, utenti, contatti) sono fittizi.
