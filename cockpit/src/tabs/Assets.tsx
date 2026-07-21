import { useEffect, useState } from "react";
import { api, Asset, Program } from "../api";

function isRecent(iso: string | null): boolean {
  if (!iso) return false;
  const seen = new Date(iso).getTime();
  return Number.isFinite(seen) && Date.now() - seen < 24 * 60 * 60 * 1000;
}

export default function Assets({ program }: { program: Program | null }) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!program) {
      setAssets([]);
      return;
    }
    setErr(null);
    api
      .listAssets(program.id)
      .then(setAssets)
      .catch((e) => setErr((e as Error).message));
  }, [program]);

  if (!program) return <div className="empty">Select a program on the Programs tab.</div>;

  return (
    <div className="card">
      <h2>Live in-scope assets ({assets.length})</h2>
      {err && <div className="err">{err}</div>}
      {assets.length === 0 ? (
        <div className="empty">No assets recorded yet — the recon engine (Phase 1) populates these.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Kind</th>
              <th>Asset</th>
              <th>Alive</th>
              <th>Trust</th>
              <th>Found by</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id}>
                <td>
                  <span className="tag">{a.kind}</span>
                </td>
                <td className="mono">
                  {a.display_value}
                  {isRecent(a.first_seen_at) && <span className="pill" style={{ background: "var(--accent)", color: "var(--on-accent)", marginLeft: 8 }}>new</span>}
                </td>
                <td>{a.is_alive ? "✓" : "—"}</td>
                <td>{a.trust_score.toFixed(2)}</td>
                <td className="faint">{a.discovered_by ?? "—"}</td>
                <td className="faint">{(a.first_seen_at ?? "").slice(0, 10)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
