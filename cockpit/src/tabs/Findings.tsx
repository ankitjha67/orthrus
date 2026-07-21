import { useEffect, useState } from "react";
import { api, FINDING_STATUSES, Finding, Program, SEV_CLASS } from "../api";

export default function Findings({ program }: { program: Program | null }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!program) {
      setFindings([]);
      return;
    }
    setErr(null);
    api
      .listFindings(program.id)
      .then(setFindings)
      .catch((e) => setErr((e as Error).message));
  }, [program]);

  const changeStatus = async (fid: string, status: string) => {
    if (!program) return;
    try {
      const updated = await api.updateFinding(program.id, fid, { status });
      setFindings((fs) => fs.map((f) => (f.id === fid ? updated : f)));
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  if (!program) return <div className="empty">Select a program on the Programs tab.</div>;

  return (
    <div className="card">
      <h2>Findings queue ({findings.length})</h2>
      {err && <div className="err">{err}</div>}
      {findings.length === 0 ? (
        <div className="empty">No findings yet - scans promote confirmed bugs into the queue.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Priority</th>
              <th>Severity</th>
              <th>Class</th>
              <th>Title</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Tool</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>{f.priority_score?.toFixed(0) ?? "-"}</td>
                <td className={SEV_CLASS[f.severity] ?? ""}>{f.severity}</td>
                <td className="mono faint">{f.vuln_class}</td>
                <td>{f.title}</td>
                <td>{f.confidence}</td>
                <td>
                  <select
                    value={f.status}
                    onChange={(e) => changeStatus(f.id, e.target.value)}
                    style={{ padding: "3px 6px", fontSize: 12 }}
                  >
                    {FINDING_STATUSES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="faint">{f.found_by_tool}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
