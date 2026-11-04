# Valutazione

## Ground truth
`scripts/generate_dataset.py` genera realm, inventario e log **e** la verità attesa (`data/scenarios/expected-findings.json`) a partire da ciò che pianta nei dati, non dall'output del motore.

| Tipologia | Client |
|---|---|
| OIDC Authorization Code | 35 |
| OIDC Client Credentials | 25 |
| OIDC Public / SPA | 15 |
| SAML | 15 |
| Legacy / configurazioni particolari | 10 |

Casi piantati:

| BC | Positivi | Lookalike compatibili / ambigui |
|---|---|---|
| KC-BC-001 wildcard nell'host | 6 con traffico (high), 3 senza traffico (medium) | 1 client disabilitato (low); molti `https://host/*` compatibili |
| KC-BC-002 logout `redirect_uri` | 3 con `client_id` (high), 2 attribuiti per inferenza (medium), 1 anonimo | 4 client con `post_logout_redirect_uri` |
| KC-BC-003 path non normalizzati | 2 SPA via query, 1 servizio via MDC, 1 anonimo | — |
| KC-BC-004 role mapper single-valued | 2 con traffico (high), 1 senza (medium) | 3 mapper multivalued |
| KC-BC-005 controllo anonymous | sempre | — |

## Risultati per scenario (dataset dimostrativo)
| Scenario | BC applicabili | Client impattati |
|---|---|---|
| 26.5.0 → 26.6.3 | 001 | 10 |
| 22.0.5 → 26.6.3 | 001, 002, 003, 004 | 20 |
| 25.0.6 → 26.6.3 | 001, 002, 003 | 17 |
| 26.3.0 → 26.5.0 | 003 | 3 |

Le versioni di introduzione sono quelle della guida ufficiale: 001 → 26.6.3, 002 → 26.0.0, 003 → 26.4.3, 004 → 23.0.0.

## Criteri di accettazione → test
| Criterio | Verifica |
|---|---|
| Avvio riproducibile | `docker compose up` + healthcheck di Keycloak, ES, backend |
| Dataset completo | `test_realm_has_100_clients_with_expected_distribution`, `test_ingestion_indexes_chunks_and_rules_idempotently` |
| Ingestione idempotente | `test_*_idempotent` (memory) e `test_ingestion_is_idempotent_on_elasticsearch` |
| Detection accurata | `test_all_known_positives_are_detected_with_expected_confidence` (3 scenari) |
| Controllo falsi positivi | `test_compatible_clients_are_not_flagged` |
| Gestione anonymous | `test_anonymous_rule_when_client_missing`, `test_anonymous_handling`, `test_ingest_pipeline_applies_anonymous_rule` |
| RAG verificabile | `test_every_explanation_cites_its_breaking_change`, `test_ungrounded_llm_answer_is_discarded` |
| Parsing della guida reale | `tests/unit/test_upgrading_html.py` (indice = TOC, versioni da/a, categorie, id stabili) |
| Coerenza delle regole LLM | `tests/unit/test_rule_extraction.py` (registro chiuso, fingerprint, grounding, cache, approvate prevalgono) |
| Ripetibilità dei test | fixture `evidence` in `tests/breaking_changes` (request, response, versione, esito, evidenze, finding atteso) |

## Limiti noti
- `data/breaking-changes/source/upgrading-guide.html` è stato renderizzato con Asciidoctor dai sorgenti AsciiDoc ufficiali (branch `main` del 2026-11-04), perché `www.keycloak.org` non era raggiungibile dall'ambiente di sviluppo. `main` può contenere versioni non ancora pubblicate (es. 27.0.0). Il job `bc-sync` lo sostituisce con la pagina scaricata.
- Il parser è verificato sull'output Asciidoctor; la pagina del sito aggiunge header/footer ma usa lo stesso markup. Se il layout cambiasse, `warnings` nel catalogo e il controllo "0 voci estratte" lo segnalano.
- La matrice comportamentale dei test live è coerente con la guida ufficiale ma va osservata eseguendo la suite sui container reali.
- Gli embeddings di default sono hashing locale: sul corpus reale (539 voci) la voce giusta è nei primi 3 risultati per le query di test, non sempre al primo posto. Per un ranking migliore usare `EMBEDDING_BACKEND=sentence-transformers`. Le spiegazioni non ne risentono perché filtrano per `bc_id`.
