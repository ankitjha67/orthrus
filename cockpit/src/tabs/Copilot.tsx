import { useState } from "react";
import { api, CopilotHit, Program } from "../api";

export default function Copilot({ program }: { program: Program | null }) {
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<CopilotHit[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ask = async () => {
    if (!program || !query.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await api.copilot(program.id, query.trim());
      setHits(res.hits);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!program) return <div className="empty">Select a program on the Programs tab.</div>;

  return (
    <>
      <div className="card">
        <h2>Copilot</h2>
        <p className="muted">
          Grounded in <b>{program.name}</b>'s own findings and notes - it retrieves and cites,
          never invents. (LLM synthesis + vendored knowledge land with the embeddings backend.)
        </p>
        <div className="row">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && ask()}
            placeholder="e.g. what SSRF have I found · cloudflare WAF notes"
          />
          <button className="btn fit" disabled={busy || !query.trim()} onClick={ask}>
            {busy ? "…" : "Ask"}
          </button>
        </div>
        {err && <div className="err">{err}</div>}
      </div>

      {hits !== null && (
        <div className="card">
          <h2>{hits.length} result(s)</h2>
          {hits.length === 0 ? (
            <div className="empty">Nothing in your data matches - the copilot won't make something up.</div>
          ) : (
            hits.map((h, i) => (
              <div key={i} style={{ padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
                <div>
                  <span className="tag">{h.source.split(":")[0]}</span>
                  <b>{h.title}</b>
                  <span className="faint" style={{ marginLeft: 8 }}>score {h.score.toFixed(2)}</span>
                </div>
                <div className="muted" style={{ marginTop: 4, whiteSpace: "pre-wrap" }}>{h.snippet}</div>
              </div>
            ))
          )}
        </div>
      )}
    </>
  );
}
