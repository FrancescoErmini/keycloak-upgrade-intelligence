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
| 25.0.6 → 26.6.3 | 001, 002, 003, 004 | 20 |
| 26.3.0 → 26.5.0 | 003 | 3 |

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
| Ripetibilità dei test | fixture `evidence` in `tests/breaking_changes` (request, response, versione, esito, evidenze, finding atteso) |

## Limiti noti
- `keycloak-26-upgrading.html` è un estratto curato che parafrasa la guida ufficiale; le regole hanno `verified_against_official_docs: false` finché non vengono riviste. Con `BC_SOURCE_URL` si ingerisce la guida ufficiale: le regole il cui `source_quote` non compare verbatim vengono **rifiutate** dalla validazione, ed è il comportamento voluto.
- La matrice comportamentale dei test live (`matrix_verified: false`) deriva dal report tecnico e va confermata eseguendo la suite sulle versioni reali.
- Gli embeddings di default sono hashing locale (deterministici, senza download): adeguati al corpus ridotto; per corpora ampi usare `EMBEDDING_BACKEND=sentence-transformers`.
