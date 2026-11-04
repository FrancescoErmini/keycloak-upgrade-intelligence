# Sync delle breaking changes dalla guida ufficiale

## Sorgente
`https://www.keycloak.org/docs/latest/upgrading/index.html`: pagina statica generata da Asciidoctor a partire da `docs/documentation/upgrading` del repository keycloak/keycloak.

Struttura verificata:

```
h2  Migration Changes (#migration-changes)
  h3  Migrating to 26.6.3                       ← versione "to"; la "from" è la versione precedente nell'indice
    h4  Breaking changes | Notable changes | Deprecated features | Removed features | End of Life features
      h5  <voce>                                ← entry
        h6  <sotto-sezione della voce>
  h3  Migrating to 26.0.0                       ← versioni ≤ 26.0.0: niente categorie,
    h4  <voce>                                    le voci sono direttamente sotto la versione → "uncategorized"
```

Gli id HTML delle categorie sono posizionali (`_breaking_changes_5`) e cambiano quando esce una nuova versione: la chiave stabile di una voce è `kc-<versione>-<categoria>-<slug titolo>`.

## Job manuale

```bash
# nello stack
docker compose --profile jobs run --rm bc-sync                    # completo
docker compose --profile jobs run --rm bc-sync --dry-run          # solo download + parse + diff
docker compose --profile jobs run --rm bc-sync --max-entries 30   # limita le chiamate LLM (costi)

# in locale
cd backend && python -m app.jobs.sync_breaking_changes --no-index
python -m app.jobs.sync_breaking_changes --file pagina-salvata.html --no-llm
```

Passi e file prodotti (in `data/breaking-changes/`):

| Passo | Output |
|---|---|
| download | `source/upgrading-guide.html`, `source/meta.json` |
| parse HTML → JSON | `catalog.json` |
| diff col sync precedente | `sync-report.json` → `diff` (added / changed / removed, nuove versioni) |
| analisi LLM | `rules/llm-candidates.json` (`candidate` / `no-checks` / `rejected` / `error`) |
| report | `sync-report.json` → `llm.checks_by_data_source`, `llm.shared_filters`, `llm.manual_checks_by_data_source` |
| indicizzazione | `kc-bc-knowledge` (tutte le voci), `kc-bc-rules` (approvate + candidate) |

Al LLM vanno solo le voci con versione ≥ `BC_MIN_VERSION` (default 22.0.0) e categoria in `BC_LLM_CATEGORIES` (default breaking, deprecated, removed, end-of-life, uncategorized). Le voci coperte da `rules/approved-rules.json` non vengono mai inviate.

## Formato del catalogo

```json
{
  "schema_version": "1.0",
  "source_url": "https://www.keycloak.org/docs/latest/upgrading/index.html",
  "fetched_at": "...", "content_sha256": "...",
  "stats": {"versions": 56, "entries": 539, "by_category": {"breaking": 72, "notable": 203, "...": 0}},
  "warnings": [],
  "index": [
    {"version": "26.6.3", "from_version": "26.6.2", "to_version": "26.6.3", "anchor": "_migrating_to_26_6_3",
     "categories": {"breaking": 3, "notable": 4}, "entries": ["kc-26.6.3-breaking-valid-redirect-uris-..."]}
  ],
  "entries": [
    {"entry_id": "kc-26.6.3-breaking-valid-redirect-uris-...", "version": "26.6.3",
     "from_version": "26.6.2", "to_version": "26.6.3", "category": "breaking",
     "title": "Valid redirect URIs for clients do not accept wildcards for hostname anymore",
     "anchor": "_valid_redirect_uris_...", "url": "https://...#_valid_redirect_uris_...",
     "text": "...", "code_blocks": [], "links": [], "content_hash": "..."}
  ]
}
```

`warnings` segnala divergenze tra indice (TOC) e corpo della pagina e versioni senza voci: se il layout del sito cambia, il job si ferma senza scrivere nulla quando non estrae alcuna voce.

## Dal testo della guida ai check
Il prompt (in inglese, `backend/app/llm/prompts.py`) chiede all'LLM di ragionare come un SRE che prepara l'upgrade: per ogni voce elenca **tutte** le verifiche utili su un'installazione reale, una per oggetto in `checks`. Ogni check ha:

| Campo | Contenuto |
|---|---|
| `data_source` | da dove si prende l'evidenza (enum, vedi sotto), **anche** quando oggi non la leggiamo |
| `what_to_check` / `how_to_check` / `impact_signal` | testo libero: cosa guardare, come, cosa significa "impattato" |
| `scope` | `client` se il check individua client specifici, altrimenti `realm` / `server` |
| `detector` + `params` | detector eseguibile del registro, oppure `none` (verifica manuale descritta a parole) |
| `evidence_quote` | frase della voce, verbatim |

Fonti dati (`DATA_SOURCES` in `detection/detectors.py`): `realm_export`, `access_log`, `event_log`, `server_log`, `server_info`, `server_config`, `admin_api`, `database`, `custom_extensions`, `themes`, `operator`, `client_application`.

Un detector impone la propria fonte (es. `http.endpoint.query_param` → `access_log`), così lo stesso filtro ha sempre la stessa fonte. I check non validi (citazione non verbatim, parametro inventato) vengono scartati singolarmente; la regola resta se almeno un check è valido.

## Filtro per fonte dati in detection
`AVAILABLE_DATA_SOURCES` (default `realm_export,access_log,event_log,server_log`, sovrascrivibile per singolo assessment con `data_sources` in `POST /api/assessments`) decide cosa si esegue:

- check con detector **e** fonte disponibile → eseguito;
- fonte non disponibile → `checks_not_executed` con motivo `data source 'x' not available`;
- detector `none` → `checks_not_executed` con motivo `manual check`.

Se più check della stessa BC colpiscono lo stesso client, il finding è uno solo con le evidenze di tutti (`checks_matched`). La dashboard mostra le verifiche non eseguite raggruppate per fonte.

## Prova con OpenAI (gpt-4.1-mini, 2026-11-04)
Cinque voci reali, due esecuzioni ciascuna, regole approvate come esempi (tolta quella della voce sotto test):

| Voce | Check eseguibili | Stabile tra i 2 giri |
|---|---|---|
| 26.0.0 legacy `redirect_uri` sul logout | `http.endpoint.query_param` (oidc-logout, redirect_uri) + check manuali | sì |
| 26.4.3 deprecated non-normalized paths | `http.path.non_normalized` + `server_config` manuale | sì |
| 26.6.3 lunghezza parametri token endpoint | nessuno, solo check manuali (dopo la correzione del prompt) | sì |
| 26.5.0 aggiornamenti PostgreSQL | nessuno (dopo la correzione del prompt) | sì |
| 26.5.0 `session_state`/`sid` non più UUID | nessuno: realm_export / event_log / client_application manuali | sì sui check eseguibili; i check manuali variano |

Il testo dei check manuali e la loro lista variano tra un giro e l'altro (è testo libero); i check eseguibili no. La cache per voce rende comunque stabile il risultato tra un sync e l'altro.

## Promuovere un candidato
1. Leggere `rules/llm-candidates.json` (o il report).
2. Copiare la regola in `rules/approved-rules.json` con un `bc_id` definitivo (`KC-BC-0xx`), rivedendo severità e remediation.
3. Rilanciare il job (o `POST /api/ingest/breaking-changes`): da quel momento la regola viene eseguita.

## Coerenza delle label dell'LLM
Vedi [ADR 0005](adr/0005-closed-detector-registry.md): l'analisi è libera, ma ciò che viene eseguito passa solo dal registro chiuso dei detector (enum strict, parametri canonici, fingerprint, grounding, cache per hash, esempi dalle regole approvate).
