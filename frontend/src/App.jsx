import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api.js";

const READINESS = {
  ready: { label: "Ready", icon: "✓", cls: "good" },
  "review-required": { label: "Review required", icon: "!", cls: "warning" },
  blocked: { label: "Blocked", icon: "✕", cls: "critical" },
};
const SEVERITY_CLS = { critical: "critical", high: "serious", medium: "warning", low: "neutral", info: "neutral" };
const SEVERITY_ICON = { critical: "✕", high: "▲", medium: "!", low: "•", info: "i" };

function StatusChip({ kind, label, icon }) {
  return (
    <span className={`chip chip-${kind}`}>
      <span aria-hidden="true">{icon}</span> {label}
    </span>
  );
}

function Tile({ label, value, hint }) {
  return (
    <div className="tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {hint && <div className="tile-hint">{hint}</div>}
    </div>
  );
}

function CategoryBars({ data }) {
  const rows = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, v]) => v));
  if (!rows.length) return <p className="muted">Nessun finding per questa coppia di versioni.</p>;
  return (
    <div className="bars" role="table" aria-label="Impacted clients by category">
      {rows.map(([k, v]) => (
        <div className="bar-row" role="row" key={k} title={`${k}: ${v} client`}>
          <span className="bar-label" role="cell">{k}</span>
          <span className="bar-track" role="cell">
            <span className="bar-fill" style={{ width: `${(v / max) * 100}%` }} />
          </span>
          <span className="bar-value" role="cell">{v}</span>
        </div>
      ))}
    </div>
  );
}

function Evidence({ items }) {
  return (
    <ul className="evidence">
      {items.map((e, i) => (
        <li key={i}>
          <span className={`tag tag-${e.type}`}>{e.type}</span>{" "}
          {e.type === "runtime" && (
            <>
              <code>{e.method} {e.path}{e.query ? `?${e.query}` : ""}</code> → {e.status ?? e.event_action}
              <span className="muted"> · {e.timestamp} · </span>
              <span className={`origin origin-${e.origin}`}>{e.origin}</span>
              {e.attribution !== "explicit" && <span className="muted"> · attribuzione: {e.attribution}</span>}
            </>
          )}
          {e.type === "static" && (
            <>
              <code>{typeof e.value === "string" ? e.value : JSON.stringify(e.value)}</code>
              {e.suggested_value && (
                <> → suggerito <code>{typeof e.suggested_value === "string" ? e.suggested_value : JSON.stringify(e.suggested_value)}</code></>
              )}
              {e.note && <span className="muted"> · {e.note}</span>}
            </>
          )}
          {e.type === "aggregate" && (
            <>
              {e.total} chiamate non attribuite ·{" "}
              {Object.entries(e.by_endpoint).slice(0, 5).map(([p, n]) => `${p} (${n})`).join(", ")}
            </>
          )}
          {e.type === "note" && <span className="muted">{e.note}</span>}
        </li>
      ))}
    </ul>
  );
}

function FindingDetail({ finding, onClose }) {
  const [exp, setExp] = useState(null);
  useEffect(() => {
    setExp(null);
    api.explanation(finding.finding_id).then(setExp).catch(() => setExp({ explanation: "Spiegazione non disponibile." }));
  }, [finding.finding_id]);
  return (
    <aside className="drawer" aria-label="Finding detail">
      <button className="close" onClick={onClose} aria-label="Chiudi">×</button>
      <h2>{finding.client_id}</h2>
      <p className="muted">
        {finding.bc_id} · {finding.bc_title} · {finding.source_version} → {finding.target_version}
      </p>
      <div className="meta">
        <StatusChip kind={SEVERITY_CLS[finding.severity]} icon={SEVERITY_ICON[finding.severity]} label={finding.severity} />
        <span>Confidenza: <b>{finding.confidence_label}</b> ({finding.confidence})</span>
        <span>Fonti: {finding.detection_sources.join(" + ")}</span>
        {finding.checks_matched?.length > 0 && <span className="muted">verifiche: {finding.checks_matched.join(", ")}</span>}
        {!finding.client_identified && <span className="muted">client non identificato</span>}
      </div>
      {finding.inventory?.owner_team && (
        <p className="muted">Owner: {finding.inventory.owner_team} · criticità {finding.inventory.business_criticality}</p>
      )}
      <h3>Remediation</h3>
      <p>{finding.remediation}</p>
      <h3>Spiegazione {exp?.generator && <span className="muted">({exp.generator})</span>}</h3>
      <p>{exp ? exp.explanation : "…"}</p>
      {exp?.citations?.length > 0 && (
        <ul className="citations">
          {exp.citations.map((c, i) => (
            <li key={i}>
              <b>{c.bc_id}</b> {c.section_anchor && <>· <a href={c.source_url} target="_blank" rel="noreferrer">{c.section_anchor}</a></>}
              {c.quote && <blockquote>{c.quote}</blockquote>}
            </li>
          ))}
        </ul>
      )}
      <h3>Evidenze ({finding.evidence_count})</h3>
      <Evidence items={finding.evidence} />
    </aside>
  );
}

function RunForm({ onDone }) {
  const [source, setSource] = useState("26.5.0");
  const [target, setTarget] = useState("26.6.3");
  const [origins, setOrigins] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const a = await api.runAssessment({
        source_version: source,
        target_version: target,
        log_origins: origins === "all" ? null : [origins],
      });
      onDone(a);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="run" onSubmit={submit}>
      <label>Da <input value={source} onChange={(e) => setSource(e.target.value)} size={8} /></label>
      <label>A <input value={target} onChange={(e) => setTarget(e.target.value)} size={8} /></label>
      <label>
        Log{" "}
        <select value={origins} onChange={(e) => setOrigins(e.target.value)}>
          <option value="all">tutte le origini</option>
          <option value="synthetic-fixture">synthetic-fixture</option>
          <option value="keycloak-runtime">keycloak-runtime</option>
        </select>
      </label>
      <button disabled={busy}>{busy ? "Analisi…" : "Esegui assessment"}</button>
      {error && <span className="error">{error}</span>}
    </form>
  );
}

export default function App() {
  const [assessments, setAssessments] = useState([]);
  const [current, setCurrent] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState({ q: "", bc: "", severity: "" });
  const [error, setError] = useState(null);

  const load = async (preferId) => {
    try {
      const list = await api.assessments();
      setAssessments(list);
      const pick = list.find((a) => a.assessment_id === preferId) || list[0] || null;
      setCurrent(pick);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (!current) return;
    setSelected(null);
    api.findings(current.assessment_id).then(setFindings).catch((e) => setError(e.message));
  }, [current?.assessment_id, current?.created_at]);

  const visible = useMemo(
    () => findings.filter((f) =>
      (!filter.q || f.client_id.includes(filter.q.toLowerCase())) &&
      (!filter.bc || f.bc_id === filter.bc) &&
      (!filter.severity || f.severity === filter.severity)),
    [findings, filter]
  );
  const bcIds = [...new Set(findings.map((f) => f.bc_id))].sort();

  if (error && !assessments.length) {
    return (
      <main className="empty">
        <h1>Upgrade Readiness</h1>
        <p className="error">Backend non raggiungibile: {error}</p>
      </main>
    );
  }
  if (!current) {
    return (
      <main className="empty">
        <h1>Upgrade Readiness</h1>
        <p>Nessun assessment disponibile.</p>
        <button onClick={() => api.bootstrap().then(() => load())}>Carica dataset dimostrativo</button>
      </main>
    );
  }

  const s = current.summary;
  const r = READINESS[current.status] || READINESS["review-required"];
  return (
    <main>
      <header>
        <div>
          <h1>Upgrade Readiness</h1>
          <p className="muted">
            Keycloak {current.source_version} → {current.target_version} · snapshot {current.snapshot_id}
            {current.parameters?.label && ` · ${current.parameters.label}`}
          </p>
        </div>
        <StatusChip kind={r.cls} icon={r.icon} label={r.label} />
      </header>

      <section className="toolbar">
        <label>
          Assessment{" "}
          <select value={current.assessment_id} onChange={(e) => setCurrent(assessments.find((a) => a.assessment_id === e.target.value))}>
            {assessments.map((a) => (
              <option key={a.assessment_id} value={a.assessment_id}>
                {a.source_version} → {a.target_version} {a.parameters?.label ? `(${a.parameters.label})` : ""}
              </option>
            ))}
          </select>
        </label>
        <RunForm onDone={(a) => load(a.assessment_id)} />
      </section>

      <section className="tiles">
        <Tile label="Clients assessed" value={s.clients_assessed} />
        <Tile label="Impacted clients" value={s.impacted_clients} />
        <Tile label="Detected BC" value={s.detected_bc} hint={`${s.applicable_rules.filter((b) => b !== "KC-BC-005").length} applicabili`} />
        <Tile label="Anonymous calls" value={s.anonymous_calls} hint="client_id = anonymous" />
      </section>

      <section className="panel">
        <h2>Impacted clients by category</h2>
        <CategoryBars data={s.impacted_by_category} />
        {s.skipped_rules.length > 0 && (
          <p className="muted small">
            Non applicabili a questa coppia di versioni:{" "}
            {s.skipped_rules.map((x) => `${x.bc_id} (${x.introduced_in})`).join(", ")}
          </p>
        )}
      </section>

      {s.checks_not_executed?.length > 0 && (
        <section className="panel">
          <h2>Verifiche non eseguite ({s.checks_not_executed.length})</h2>
          <p className="muted small">
            Fonti dati disponibili: {(s.data_sources_available || []).join(", ")} · eseguite {s.checks_executed} verifiche
          </p>
          <div className="table-wrap">
            <table>
              <thead><tr><th>BC</th><th>Fonte dati</th><th>Verifica</th><th>Motivo</th></tr></thead>
              <tbody>
                {s.checks_not_executed.map((c) => (
                  <tr key={`${c.bc_id}-${c.check_id}`}>
                    <td>{c.bc_id}</td><td>{c.data_source}</td>
                    <td className="wrap">{c.what_to_check || c.check_id}</td><td className="muted">{c.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Findings ({visible.length})</h2>
          <div className="filters">
            <input placeholder="client id…" value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} />
            <select value={filter.bc} onChange={(e) => setFilter({ ...filter, bc: e.target.value })}>
              <option value="">tutte le BC</option>
              {bcIds.map((b) => <option key={b}>{b}</option>)}
            </select>
            <select value={filter.severity} onChange={(e) => setFilter({ ...filter, severity: e.target.value })}>
              <option value="">tutte le severità</option>
              {["critical", "high", "medium", "low", "info"].map((x) => <option key={x}>{x}</option>)}
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Client</th><th>BC</th><th>Categoria</th><th>Severità</th><th>Confidenza</th>
                <th>Fonti</th><th className="num">Evidenze</th><th className="num">Risk</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <tr key={f.finding_id} onClick={() => setSelected(f)} className={selected?.finding_id === f.finding_id ? "sel" : ""}>
                  <td><b>{f.client_id}</b>{!f.client_identified && <span className="muted"> (non attribuito)</span>}</td>
                  <td title={f.bc_title}>{f.bc_id}</td>
                  <td>{f.category_label}</td>
                  <td><StatusChip kind={SEVERITY_CLS[f.severity]} icon={SEVERITY_ICON[f.severity]} label={f.severity} /></td>
                  <td>{f.confidence_label}</td>
                  <td>{f.detection_sources.join(" + ")}</td>
                  <td className="num">{f.evidence_count}</td>
                  <td className="num">{f.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </main>
  );
}
