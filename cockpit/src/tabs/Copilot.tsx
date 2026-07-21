import { Program } from "../api";

export default function Copilot({ program }: { program: Program | null }) {
  return (
    <div className="card">
      <h2>Copilot</h2>
      <p className="muted">
        A copilot grounded in <b>your own</b> data — notes, submissions, and cross-run finding history —
        answering only from what it retrieves, never inventing a vulnerability. Available today at the CLI:
        <code> orthrus copilot "…"</code>. The embeddings-backed chat (LanceDB + BGE rerank over your corpus
        plus vendored HackTricks / PayloadsAllTheThings) lands in Phase 4.
      </p>
      {program && <p className="faint">Context: {program.name}</p>}
    </div>
  );
}
