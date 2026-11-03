async function req(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export const api = {
  assessments: () => req("/assessments"),
  findings: (id) => req(`/assessments/${id}/findings`),
  client: (id, clientId) => req(`/assessments/${id}/clients/${encodeURIComponent(clientId)}`),
  explanation: (findingId) => req(`/findings/${findingId}/explanation`),
  runAssessment: (body) => req("/assessments", { method: "POST", body: JSON.stringify(body) }),
  bootstrap: () => req("/bootstrap", { method: "POST" }),
};
