import { useState } from "react";
import { api, IntruderResponse, Program, ReplayResponse } from "../api";

const SAMPLE_REPEATER = "GET / HTTP/1.1\nHost: example.com\n\n";
const SAMPLE_INTRUDER = "GET /item?id=§1§ HTTP/1.1\nHost: example.com\n\n";
const MODES = ["sniper", "batteringram", "pitchfork", "clusterbomb"];

function scopeFor(program: Program | null, fallback: string): string {
  return program ? program.name : fallback;
}

/** Repeater + Intruder - drive the scope-enforced tools over the REST API. */
export default function Workbench({ program }: { program: Program | null }) {
  const [sub, setSub] = useState<"repeater" | "intruder">("repeater");
  return (
    <div className="panel">
      <div className="subtabs">
        <button className={"chip" + (sub === "repeater" ? " active" : "")} onClick={() => setSub("repeater")}>
          Repeater
        </button>
        <button className={"chip" + (sub === "intruder" ? " active" : "")} onClick={() => setSub("intruder")}>
          Intruder
        </button>
      </div>
      {sub === "repeater" ? <Repeater program={program} /> : <Intruder program={program} />}
    </div>
  );
}

function Repeater({ program }: { program: Program | null }) {
  const [raw, setRaw] = useState(SAMPLE_REPEATER);
  const [scope, setScope] = useState("");
  const [scheme, setScheme] = useState("https");
  const [resp, setResp] = useState<ReplayResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function send() {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.replay({ raw_request: raw, scope: scopeFor(program, scope), scheme });
      setResp(r);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wb">
      <p className="faint">
        Resend a raw request, scope-enforced. Scope: <code>{scopeFor(program, scope || "(none)")}</code>
      </p>
      <textarea className="raw" value={raw} onChange={(e) => setRaw(e.target.value)} rows={12} spellCheck={false} />
      <div className="row">
        {!program && (
          <input className="in" placeholder="scope (host / CIDR)" value={scope} onChange={(e) => setScope(e.target.value)} />
        )}
        <select className="in" value={scheme} onChange={(e) => setScheme(e.target.value)}>
          <option>https</option>
          <option>http</option>
        </select>
        <button className="btn" disabled={busy} onClick={send}>{busy ? "Sending..." : "Send"}</button>
      </div>
      {err && <div className="err">{err}</div>}
      {resp && (
        <div className="resp">
          {resp.error ? (
            <div className="err">{resp.error}</div>
          ) : (
            <>
              <div className="respline">
                <b>{resp.status}</b> {resp.reason} · {resp.elapsed_ms} ms · {resp.body.length.toLocaleString()} bytes
              </div>
              <pre className="body">{resp.body.slice(0, 20000)}</pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Intruder({ program }: { program: Program | null }) {
  const [raw, setRaw] = useState(SAMPLE_INTRUDER);
  const [scope, setScope] = useState("");
  const [mode, setMode] = useState("sniper");
  const [match, setMatch] = useState("");
  const [payloadText, setPayloadText] = useState("1\n2\n3'\n999999");
  const [rep, setRep] = useState<IntruderResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setErr(null);
    setRep(null);
    // one payload set per blank-line-separated block; each line = a payload.
    const sets = payloadText.split(/\n\s*\n/).map((b) => b.split("\n").map((s) => s.trim()).filter(Boolean));
    try {
      const r = await api.intruder({
        raw_request: raw,
        payloads: sets.filter((s) => s.length),
        mode,
        scope: scopeFor(program, scope),
        match: match || null,
      });
      setRep(r);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const interesting = rep?.results.filter((r) => r.anomaly || r.matched) ?? [];

  return (
    <div className="wb">
      <p className="faint">
        Mark positions with <code>§...§</code>. Payload sets are separated by a blank line (one per position
        for pitchfork/clusterbomb). Scope-enforced.
      </p>
      <textarea className="raw" value={raw} onChange={(e) => setRaw(e.target.value)} rows={8} spellCheck={false} />
      <div className="row">
        <label className="lbl">Payloads</label>
        <textarea className="raw sm" value={payloadText} onChange={(e) => setPayloadText(e.target.value)} rows={5} spellCheck={false} />
      </div>
      <div className="row">
        {!program && (
          <input className="in" placeholder="scope (host / CIDR)" value={scope} onChange={(e) => setScope(e.target.value)} />
        )}
        <select className="in" value={mode} onChange={(e) => setMode(e.target.value)}>
          {MODES.map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <input className="in" placeholder="grep match (optional)" value={match} onChange={(e) => setMatch(e.target.value)} />
        <button className="btn" disabled={busy} onClick={run}>{busy ? "Attacking..." : "Attack"}</button>
      </div>
      {err && <div className="err">{err}</div>}
      {rep && (
        <div className="resp">
          <div className="respline">
            {rep.total} request(s) · baseline {JSON.stringify(rep.baseline)} · {interesting.length} interesting
          </div>
          <table className="tbl">
            <thead>
              <tr><th>payload(s)</th><th>status</th><th>length</th><th>ms</th><th>flags</th></tr>
            </thead>
            <tbody>
              {(interesting.length ? interesting : rep.results).slice(0, 100).map((r, i) => (
                <tr key={i} className={r.matched ? "hit" : r.anomaly ? "anom" : ""}>
                  <td><code>{r.payloads.join(" / ")}</code></td>
                  <td>{r.status ?? "-"}</td>
                  <td>{r.length ?? "-"}</td>
                  <td>{r.elapsed_ms}</td>
                  <td>{[r.matched && "MATCH", r.anomaly && "anomaly", r.error].filter(Boolean).join(" ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
