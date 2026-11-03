# ADR 0002 — LLM solo per interpretare le breaking changes, detection deterministica

**Stato:** accettato · **Data:** 2026-11-04

## Decisione
- Pipeline A può usare un LLM (locale, Ollama) per **proporre** regole JSON; le proposte vengono validate (citazione verbatim del passaggio, termini ed eventuali parametri presenti nel testo, campi/operatori di un DSL chiuso, versione coerente con la sezione) e salvate come `candidate`.
- Solo le regole `approved` (manifest curato o promosse da revisione umana) sono eseguite dal motore.
- Pipeline B e C sono deterministiche. La detection runtime non richiede un modello.
- Le spiegazioni RAG sono accettate solo se citano il `bc_id`; altrimenti si usa un template deterministico con citazione.

## Conseguenze
Nessun costo API obbligatorio; il modello non può inventare endpoint o comportamenti che finiscano nei findings.
