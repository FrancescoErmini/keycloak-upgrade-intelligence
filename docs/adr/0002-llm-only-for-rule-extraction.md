# ADR 0002 — LLM solo per interpretare le breaking changes, detection deterministica

**Stato:** accettato · **Data:** 2026-11-04

## Decisione
- Il job manuale di sync usa un LLM (OpenAI con Structured Outputs; in alternativa Ollama) per **mappare** ogni voce della guida sul registro chiuso dei detector (ADR 0005); le proposte vengono validate (citazione verbatim, parametri presenti nel testo, valori ammessi dal registro) e salvate come `candidate`.
- Solo le regole `approved` (`rules/approved-rules.json`, revisione umana) sono eseguite dal motore.
- Pipeline B e C sono deterministiche. La detection runtime non richiede un modello.
- Le spiegazioni RAG sono accettate solo se citano il `bc_id`; altrimenti si usa un template deterministico con citazione.

## Conseguenze
Nessun costo API obbligatorio; il modello non può inventare endpoint o comportamenti che finiscano nei findings.
