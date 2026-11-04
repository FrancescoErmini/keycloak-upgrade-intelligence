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
| mapping LLM | `rules/llm-candidates.json` (`candidate` / `rejected` / `not-detectable` / `error`) |
| report di coerenza | `sync-report.json` → `llm.shared_filters`, `llm.detector_proposals` |
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

## Promuovere un candidato
1. Leggere `rules/llm-candidates.json` (o il report).
2. Copiare la regola in `rules/approved-rules.json` con un `bc_id` definitivo (`KC-BC-0xx`), rivedendo severità e remediation.
3. Rilanciare il job (o `POST /api/ingest/breaking-changes`): da quel momento la regola viene eseguita.

## Coerenza delle label dell'LLM
Vedi [ADR 0005](adr/0005-closed-detector-registry.md): registro chiuso dei detector, output strict con enum, canonicalizzazione + fingerprint, grounding, cache per hash, esempi dalle regole approvate, `proposed_detector` come unica via d'uscita.
