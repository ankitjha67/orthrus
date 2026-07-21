import { useState } from "react";
import { api, NewProgram, Program } from "../api";

const PLATFORMS = ["h1", "bc", "int", "ywh", "im", "self", "direct"];

export default function Programs({
  programs,
  selected,
  onSelect,
  onChange,
  health,
}: {
  programs: Program[];
  selected: string | null;
  onSelect: (id: string) => void;
  onChange: () => void;
  health: boolean;
}) {
  const [form, setForm] = useState<NewProgram>({ name: "", authorization_source: "", platform: "h1" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setErr(null);
    setBusy(true);
    try {
      await api.createProgram(form);
      setForm({ name: "", authorization_source: "", platform: "h1" });
      onChange();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    if (!window.confirm("Delete this program and all its assets/findings?")) return;
    try {
      await api.deleteProgram(id);
      onChange();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <>
      {!health && (
        <div className="err">
          API offline - start it with <code>orthrus serve</code>.
        </div>
      )}

      <div className="card">
        <h2>New program</h2>
        {err && <div className="err">{err}</div>}
        <div className="row">
          <div>
            <label>Name</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Acme Corp"
            />
          </div>
          <div className="fit" style={{ minWidth: 130 }}>
            <label>Platform</label>
            <select value={form.platform} onChange={(e) => setForm({ ...form, platform: e.target.value })}>
              {PLATFORMS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
        </div>
        <label>
          Authorization source <span className="faint">(required - deny-by-default)</span>
        </label>
        <input
          value={form.authorization_source}
          onChange={(e) => setForm({ ...form, authorization_source: e.target.value })}
          placeholder="https://hackerone.com/acme · signed:… · direct:… · self-owned-lab"
        />
        <div style={{ marginTop: 14 }}>
          <button
            className="btn"
            disabled={busy || !form.name || !form.authorization_source}
            onClick={create}
          >
            Create program
          </button>
        </div>
      </div>

      <div className="card">
        <h2>Programs ({programs.length})</h2>
        {programs.length === 0 ? (
          <div className="empty">No programs yet - create one above.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Platform</th>
                <th>Authorization</th>
                <th>Priority</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {programs.map((p) => (
                <tr
                  key={p.id}
                  className="rowlink"
                  onClick={() => onSelect(p.id)}
                  style={p.id === selected ? { outline: "1px solid var(--accent)" } : undefined}
                >
                  <td>
                    <b>{p.name}</b> {p.is_paused && <span className="tag">paused</span>}
                    {p.authorization_source === "self-owned-lab" && (
                      <span className="tag badge-lab">lab</span>
                    )}
                  </td>
                  <td>
                    <span className="tag">{p.platform}</span>
                  </td>
                  <td className="mono faint">{p.authorization_source.slice(0, 46)}</td>
                  <td>{p.priority}</td>
                  <td>
                    <button
                      className="btn ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        remove(p.id);
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
