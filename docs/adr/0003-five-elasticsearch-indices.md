# ADR 0003 — Cinque indici Elasticsearch

**Stato:** accettato · **Data:** 2026-11-04

| Indice | Contenuto |
|---|---|
| `kc-bc-knowledge` | chunk della documentazione + `dense_vector` (retrieval) |
| `kc-bc-rules` | regole JSON validate (`approved` / `candidate`) |
| `kc-realm-snapshots` | un documento per client + documento `snapshot` |
| `kc-runtime-logs` | access log, eventi, log applicativi (con `default_pipeline` per la regola anonymous) |
| `kc-impact-findings` | findings + documento `assessment` di riepilogo |

Correlazione tramite `snapshot_id`, `bc_id`, `client_id`, `assessment_id`. Tutti gli id sono deterministici (hash del contenuto), quindi l'ingestione è idempotente. I log potranno evolvere in data stream con ILM.
