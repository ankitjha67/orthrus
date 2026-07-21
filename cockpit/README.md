# ORTHRUS Cockpit (v2.0)

The operator cockpit - a React 18 + Vite + TypeScript SPA that talks to the
ORTHRUS operator-graph REST API (`orthrus/api/programs.py`). It runs **two ways**
from the same code:

- **Web** - served same-origin by the backend at `/cockpit` (no desktop toolchain
  needed).
- **Desktop** - wrapped by **Tauri 2.0** (`src-tauri/`) into a native window.

Palette is red / white / black only (theme-aware), matching the rest of ORTHRUS.

## Run it as a web app (simplest)

```bash
npm --prefix cockpit install
npm --prefix cockpit run build          # → cockpit/dist
orthrus serve --cockpit                  # cockpit at http://127.0.0.1:8000/cockpit/
```

## Develop (hot reload)

```bash
orthrus serve                            # API on :8000 (separate terminal)
npm --prefix cockpit run dev             # Vite on :5173, proxies /api → :8000
```

## Build the desktop app (Tauri)

Needs the Rust toolchain (`rustc`/`cargo`) plus the Tauri CLI:

```bash
npm --prefix cockpit install -D @tauri-apps/cli
npm --prefix cockpit run tauri dev       # native window (loads the SPA)
npm --prefix cockpit run tauri build     # bundle a desktop binary
```

> Bundling is disabled by default in `src-tauri/tauri.conf.json` (`bundle.active:
> false`) so `tauri dev` runs without app icons; add icons + flip that flag to
> package an installer.

## Layout

```
cockpit/
  src/            React app - App shell + tabs/ (Programs, Assets, Findings, Reports, Copilot)
  src/api.ts      typed client for the operator-graph REST API
  src-tauri/      Tauri 2.0 desktop wrapper (Rust)
  vite.config.ts  base "/cockpit/" in prod, "/" (+ /api proxy) in dev
```
