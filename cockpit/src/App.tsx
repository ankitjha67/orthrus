import { useCallback, useEffect, useState } from "react";
import { api, Health, Program } from "./api";
import Programs from "./tabs/Programs";
import Assets from "./tabs/Assets";
import Findings from "./tabs/Findings";
import Reports from "./tabs/Reports";
import Copilot from "./tabs/Copilot";
import Workbench from "./tabs/Workbench";

type Tab = "programs" | "assets" | "findings" | "reports" | "copilot" | "workbench";
const TABS: { id: Tab; label: string }[] = [
  { id: "programs", label: "Programs" },
  { id: "assets", label: "Assets" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
  { id: "copilot", label: "Copilot" },
  { id: "workbench", label: "Workbench" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("programs");
  const [programs, setPrograms] = useState<Program[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  const refreshPrograms = useCallback(async () => {
    try {
      const ps = await api.listPrograms();
      setPrograms(ps);
      setSelected((s) => (s && ps.some((p) => p.id === s) ? s : ps[0]?.id ?? null));
    } catch {
      /* backend offline - surfaced in the Programs tab */
    }
  }, []);

  useEffect(() => {
    refreshPrograms();
    api.health().then(setHealth).catch(() => setHealth(null));
  }, [refreshPrograms]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const current = programs.find((p) => p.id === selected) ?? null;

  return (
    <div className="app">
      <nav className="rail">
        <div className="brand">
          <b>ORTHRUS</b>
          <span>cockpit</span>
        </div>
        {TABS.map((t) => (
          <button
            key={t.id}
            className={"navitem" + (tab === t.id ? " active" : "")}
            onClick={() => setTab(t.id)}
          >
            <span className="dot" />
            {t.label}
          </button>
        ))}
        <div className="spacer" />
        <div className="railfoot">
          <span className={health ? "health-ok" : "health-bad"}>●</span>
          {health ? `API v${health.version}` : "API offline"}
        </div>
      </nav>

      <main className="main">
        <div className="topbar">
          <div>
            <h1>{TABS.find((t) => t.id === tab)!.label}</h1>
            <div className="sub">{current ? `Program: ${current.name}` : "No program selected"}</div>
          </div>
          <button className="toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? "☾ dark" : "☀ light"}
          </button>
        </div>

        {tab === "programs" && (
          <Programs
            programs={programs}
            selected={selected}
            onSelect={setSelected}
            onChange={refreshPrograms}
            health={!!health}
          />
        )}
        {tab === "assets" && <Assets program={current} />}
        {tab === "findings" && <Findings program={current} />}
        {tab === "reports" && <Reports program={current} />}
        {tab === "copilot" && <Copilot program={current} />}
        {tab === "workbench" && <Workbench program={current} />}
      </main>
    </div>
  );
}
