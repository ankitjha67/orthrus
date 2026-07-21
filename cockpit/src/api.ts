// Typed client for the ORTHRUS operator-graph REST API (orthrus/api/programs.py).
// Same-origin "/api" — served by `orthrus serve --cockpit` in prod, Vite-proxied in dev.

export interface Program {
  id: string;
  name: string;
  platform: string;
  authorization_source: string;
  policy_url: string | null;
  jurisdiction: string | null;
  priority: number;
  is_paused: boolean;
  is_read_only: boolean;
  reward_range: Record<string, unknown>;
  rate_limit_hint: Record<string, unknown>;
  contact_email: string | null;
  tags: string[];
  created_at: string | null;
  updated_at: string | null;
}

export interface ScopeEntry {
  id: number;
  entry_type: string;
  kind: string;
  value: string;
  ports: number[] | null;
  protocols: string[] | null;
  is_active: boolean;
  added_at: string | null;
}

export interface Asset {
  id: string;
  kind: string;
  canonical_value: string;
  display_value: string;
  is_alive: boolean;
  is_wildcard_noise: boolean;
  trust_score: number;
  fingerprint: Record<string, unknown>;
  metadata: Record<string, unknown>;
  discovered_by: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface Finding {
  id: string;
  vuln_class: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  signature: string;
  priority_score: number | null;
  cwe_id: string | null;
  cvss_v3_score: number | null;
  found_by_tool: string;
  discovered_at: string | null;
}

export interface Health {
  status: string;
  version: string;
}
export interface CostSummary {
  entries: number;
  total_usd: number;
  by_category: Record<string, number>;
  by_provider: Record<string, number>;
}

export interface NewProgram {
  name: string;
  authorization_source: string;
  platform?: string;
  policy_url?: string | null;
  jurisdiction?: string | null;
  priority?: number;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

export const api = {
  health: () => req<Health>("/health"),
  listPrograms: () => req<Program[]>("/api/programs"),
  createProgram: (body: NewProgram) =>
    req<Program>("/api/programs", { method: "POST", body: JSON.stringify(body) }),
  getProgram: (id: string) => req<Program>(`/api/programs/${id}`),
  updateProgram: (id: string, body: Partial<Program>) =>
    req<Program>(`/api/programs/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteProgram: (id: string) => req<{ deleted: string }>(`/api/programs/${id}`, { method: "DELETE" }),
  listScope: (id: string) => req<ScopeEntry[]>(`/api/programs/${id}/scope`),
  addScope: (id: string, body: Partial<ScopeEntry>) =>
    req<ScopeEntry>(`/api/programs/${id}/scope`, { method: "POST", body: JSON.stringify(body) }),
  listAssets: (id: string) => req<Asset[]>(`/api/programs/${id}/assets`),
  listFindings: (id: string) => req<Finding[]>(`/api/programs/${id}/findings`),
  updateFinding: (id: string, fid: string, body: { status?: string; assigned_to?: string }) =>
    req<Finding>(`/api/programs/${id}/findings/${fid}`, { method: "PATCH", body: JSON.stringify(body) }),
  cost: (id: string) => req<CostSummary>(`/api/programs/${id}/cost`),
  copilot: (id: string, query: string) =>
    req<{ query: string; hits: CopilotHit[] }>(`/api/programs/${id}/copilot`, {
      method: "POST",
      body: JSON.stringify({ query }),
    }),
};

export interface CopilotHit {
  source: string;
  title: string;
  snippet: string;
  score: number;
}

export const FINDING_STATUSES = [
  "new", "triaging", "confirmed", "duplicate", "not_reproducible", "filed",
  "accepted", "rewarded", "closed", "verified_fixed", "regressed", "out_of_scope",
];

export const SEV_CLASS: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};
