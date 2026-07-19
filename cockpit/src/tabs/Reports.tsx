import { useEffect, useState } from "react";
import { api, CostSummary, Program } from "../api";

export default function Reports({ program }: { program: Program | null }) {
  const [cost, setCost] = useState<CostSummary | null>(null);

  useEffect(() => {
    if (!program) {
      setCost(null);
      return;
    }
    api.cost(program.id).then(setCost).catch(() => setCost(null));
  }, [program]);

  if (!program) return <div className="empty">Select a program on the Programs tab.</div>;

  return (
    <>
      <div className="grid">
        <div className="card">
          <div className="statlabel">Spend (this program)</div>
          <div className="stat">${cost ? cost.total_usd.toFixed(4) : "0.0000"}</div>
          <div className="faint">{cost?.entries ?? 0} ledger entr(y/ies)</div>
        </div>
      </div>
      <div className="card">
        <h2>Platform-native reports</h2>
        <p className="muted">
          Submission-ready HackerOne / Bugcrowd / Intigriti / YesWeHack / Immunefi reports are produced by
          the report engine — today via <code>orthrus bounty-report --program {program.name} --platform …</code>,
          wired into this tab in Phase 3. Reports lead with <b>confirmed</b> findings, carry evidence-grounded
          PoC steps, and flag likely cross-run duplicates.
        </p>
      </div>
    </>
  );
}
