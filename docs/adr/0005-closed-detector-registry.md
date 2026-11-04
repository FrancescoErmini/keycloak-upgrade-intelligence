# ADR 0005 — Registro chiuso dei detector per le regole generate dall'LLM

**Stato:** accettato · **Data:** 2026-11-04

## Contesto
Chiedere a un LLM di "scrivere una regola di detection" per ogni voce della guida produce, per lo stesso filtro, regex, nomi di campo e label diversi a ogni esecuzione (`legacy-logout`, `logout_redirect_param`, "Deprecated logout param"…). Ne derivano findings duplicati, dashboard incoerenti e assessment non confrontabili tra un sync e l'altro.

## Decisione
1. **Vocabolario chiuso**: `backend/app/detection/detectors.py` definisce i detector (`client.redirect_uri.hostname_wildcard`, `http.endpoint.query_param`, …). Per ognuno: condizioni (DSL), categoria del finding, label. L'LLM **sceglie** un `detector` e compila parametri tipizzati, non scrive mai condizioni né label.
2. **Output vincolato**: OpenAI Structured Outputs (`json_schema`, `strict: true`); `detector`, `change_type`, `impact_area`, `severity`, `endpoint`, `grant`, `mapper_types` sono enum.
3. **Canonicalizzazione + fingerprint**: parametri non previsti scartati, valori normalizzati (minuscolo, liste ordinate); `fingerprint = detector + hash(parametri canonici)`. Stesso fingerprint ⇒ stesso filtro ⇒ stessa label.
4. **Grounding**: citazione verbatim obbligatoria; i parametri identificativi (nome parametro, attributo, tipo evento) devono comparire letteralmente nel testo della voce.
5. **Determinismo e cache**: temperatura 0 + seed; risultato memorizzato per `(hash contenuto voce, versione prompt, versione registro, modello)`. Una voce invariata non viene richiesta di nuovo, quindi un nuovo sync non può rietichettarla.
6. **Esempi few-shot** dalle regole approvate; le regole approvate prevalgono sempre sui candidati.
7. **Via d'uscita esplicita**: se nessun detector è adatto, `detector: "none"` + `proposed_detector`. Le proposte sono aggregate in `sync-report.json` (`detector_proposals`); un nuovo detector entra nel registro solo con una modifica di codice revisionata (`REGISTRY_VERSION`).

## Conseguenze
- Nuove tipologie di BC richiedono di estendere il registro: è il prezzo della coerenza, e il report dice quali servono.
- La label del finding deriva dal detector, non dalla voce: due BC diverse con lo stesso filtro condividono label e categoria (`shared_filters` nel report).
