# Architettura

```
                ┌──────────────────────┐        ┌──────────────────────┐
  data/realms → │ keycloak-source 26.5 │        │ keycloak-target 26.6 │ ← stesso realm
                │  + postgres-source   │        │  + postgres-target   │
                └──────────┬───────────┘        └──────────┬───────────┘
                 ECS JSON (access log, eventi, MDC) su volumi dedicati
                           └──────────────┬────────────────┘
                                          ▼
  data/breaking-changes ─► Pipeline A ┐  Pipeline C (log)   Pipeline B (realm) ◄─ data/realms
   (catalog + rules)                  │        │                  │
                                      ▼        ▼                  ▼
          ┌─────────────────────────── Elasticsearch ───────────────────────────┐
          │ kc-bc-knowledge │ kc-bc-rules │ kc-runtime-logs │ kc-realm-snapshots │
          └──────────────────────────────────┬──────────────────────────────────┘
                                             ▼
                          Detection (regole approved, version-aware, no LLM)
                                             ▼
                                   kc-impact-findings ──► RAG (spiegazioni citate)
                                             ▼
                              FastAPI /api ──► React dashboard  ·  Kibana
```

## Ciclo completo
Breaking change → regola eseguibile → test reale → log ECS → detection → client impattato → remediation.

## Moduli backend (`backend/app`)
| Modulo | Ruolo |
|---|---|
| `jobs/sync_breaking_changes.py` | job manuale: download guida ufficiale → catalogo JSON → mapping LLM → indicizzazione |
| `ingestion/upgrading_html.py` | parser HTML → JSON (indice versioni da/a, categorie, voci) |
| `ingestion/rule_extraction.py` | mapping LLM vincolato sul registro dei detector, cache, report di coerenza |
| `ingestion/breaking_changes.py` | Pipeline A: indicizza catalogo + regole (nessuna rete, nessun LLM) |
| `detection/detectors.py` | registro chiuso dei detector: condizioni, categorie e label definite una sola volta |
| `ingestion/realms.py` | Pipeline B: normalizzazione client (grant type, redirect URI, mapper), snapshot |
| `ingestion/logs.py` | Pipeline C: access log combined, eventi `org.keycloak.events`, MDC, regola anonymous |
| `detection/rules.py` | DSL delle condizioni + validazione di grounding |
| `detection/analyzers.py` | analisi statica, runtime (`detect` / `corroborate` / `aggregate`), inferenza attribuzione |
| `detection/scoring.py` | confidenza, risk score, readiness |
| `rag/embeddings.py`, `rag/retrieval.py` | embeddings locali, kNN, spiegazioni con citazioni |
| `llm/` | provider `none` / `ollama` e prompt vincolati |
| `store.py` | astrazione indici: `ElasticStore` e `MemoryStore` (test offline) |

## Version awareness
Una BC si valuta solo se `source < introduced_in ≤ target`. Le regole escluse compaiono in `summary.skipped_rules` con il motivo. I test live leggono la versione dal server (`/admin/serverinfo`) e confrontano l'esito con la matrice in `upgrade-scenarios.yaml`.

## Modalità delle regole
- **static**: condizione sulla configurazione del client (realm JSON).
- **runtime / detect**: i log da soli generano il finding (es. logout legacy, path non normalizzati).
- **runtime / corroborate**: il traffico aumenta la confidenza di un finding statico (il client è attivo).
- **runtime / aggregate**: controllo, un unico finding per le chiamate non attribuite.

## Scoring
| Evidenza | Confidenza |
|---|---|
| solo configurazione | 0.70 |
| configurazione + traffico | 0.95 |
| solo runtime: 1 / 2 / ≥3 hit | 0.70 / 0.80 / 0.90 |
| attribuzione per inferenza | ×0.85 |
| client disabilitato | ×0.50 |

`high` ≥ 0.85, `medium` ≥ 0.60, altrimenti `low`. `risk_score = 100 × peso severità × confidenza × peso criticità business` (dall'inventario).

## Origini dei log
`labels.origin` distingue sempre `synthetic-fixture` (dataset dimostrativo) da `keycloak-runtime` (prodotti dai container). Ogni evidenza riporta l'origine; un assessment può essere limitato a un'origine (`log_origins`).
