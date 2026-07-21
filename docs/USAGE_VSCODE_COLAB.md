# Running ORTHRUS in VS Code & Google Colab

A complete, copy-paste step-by-step guide for two of the most common setups:

- **[Part A - VS Code](#part-a--vs-code)** on your own machine (Windows / macOS / Linux): the full developer experience - integrated terminal, breakpoint debugging, test runner, linting.
- **[Part B - Google Colab](#part-b--google-colab)** in the browser: zero local install, great for a quick demo or for running on a clean Linux box. A **one-click notebook** is included.

> ### ⚠️ Authorized testing only - read this first
> ORTHRUS sends **real attack payloads** and actively tries to exploit findings.
> Only point it at systems you **own** or have **explicit written permission** to
> test. Both walkthroughs below scan the **bundled, deliberately-vulnerable
> practice target** (`tests/integration/reflecting_target.py`), which binds to
> `127.0.0.1` only - that is the safe thing to learn on. See the full
> [Legal & Ethical Use notice in the README](../README.md#-legal--ethical-use).

**Prerequisites for both paths:** Python **3.11+** and `git`. ORTHRUS's lean core
is pure-Python (wheels only) and installs with no system binaries.

---

## Part A - VS Code

### A0. Install the prerequisites
- **Python 3.11+** - verify with `python --version` (Windows may use `py --version`).
- **git** - `git --version`.
- **VS Code** with these extensions (open the Extensions panel, `Ctrl/Cmd+Shift+X`):
  - **Python** (`ms-python.python`)
  - **Pylance** (`ms-python.vscode-pylance`)
  - **Ruff** (`charliermarsh.ruff`) - matches the project's linter/formatter.

### A1. Get the code
Open VS Code's integrated terminal (`` Ctrl+` ``) and clone the repo:

```bash
git clone https://github.com/ankitjha67/orthrus.git
cd orthrus
code .          # reopens this folder in VS Code (or File → Open Folder…)
```

### A2. Create and select the Python environment
The cleanest route uses VS Code's built-in helper:

1. `Ctrl/Cmd+Shift+P` → **Python: Create Environment** → **Venv** → pick your Python 3.11+ interpreter.
   VS Code creates `.venv/` and selects it automatically.

Or do it by hand in the terminal:

```bash
python -m venv .venv
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Windows (cmd.exe):
.\.venv\Scripts\activate.bat
# macOS / Linux:
source .venv/bin/activate
```

> **PowerShell blocks the activate script?** Run this once for the session:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`, then activate again.

Then make sure VS Code uses it: `Ctrl/Cmd+Shift+P` → **Python: Select Interpreter** → choose the one inside `.venv`. The bottom-status-bar interpreter should now read `.venv`.

### A3. Install ORTHRUS
With the venv active:

```bash
pip install --upgrade pip
pip install -e ".[dev]"          # editable install + pytest/ruff/mypy
```

Optional capability extras (install only what you need):

```bash
pip install -e ".[browser]"      # Playwright headless browser (DOM/stored XSS, PDF reports)
pip install -e ".[scanners]"     # pyjwt, cryptography, sslyze, paramiko, websockets (jwt/tls scanners)
pip install -e ".[recon]"        # python-nmap (also needs the nmap binary on PATH)
pip install -e ".[postgres]"     # asyncpg + alembic (PostgreSQL backend)
pip install -e ".[distributed]"  # celery + redis (distributed scanning)

# After [browser], download Chromium once:
playwright install chromium
```

Each module self-disables cleanly if its extra is missing - the lean core still runs everything else.

### A4. Verify the install
```bash
orthrus --version
orthrus --help
orthrus doctor          # environment-readiness table: which extras/binaries are present
```

`orthrus doctor` performs **no network access** - it only checks which optional
capabilities are installed, so it's a safe first command.

### A5. First scan - the bundled practice target (two terminals)
The repo ships a deliberately-vulnerable app that exercises every scanner, bound
to `127.0.0.1` only. Run it in one terminal and scan it from another.

**Terminal 1 - start the target** (`` Ctrl+` ``, then the **+** to keep it):
```bash
python tests/integration/reflecting_target.py 8731
```

**Terminal 2 - run the full pipeline** (split the terminal with the split icon, or **+**):
```bash
orthrus scan -t http://127.0.0.1:8731 --aggressive --no-browser -o reports/demo.json --format json
```

What the flags mean:
- `-t` target URL. Scope is auto-derived from the host (printed at the top of the run).
- `--aggressive` also enables time-based blind tests and the business-logic probes.
- `--no-browser` skips the headless-browser scanners (omit it once you've run `playwright install chromium`).
- `-o … --format json` writes a JSON report (`reports/` is gitignored, so it won't clutter your tree).

You'll see the **AUTHORIZED SCOPE** panel, live recon/scan progress, then a
colour-coded findings table.

### A6. Read the report inside VS Code
- **JSON:** open `reports/demo.json` (VS Code folds/formats it).
- **HTML (nicest):** re-run with `--format html --template technical -o reports/demo.html`, then right-click the file → **Reveal in File Explorer** and open it in a browser (or use a "Live Preview"/"open in browser" extension).
- **Themed terminal view as an image** (needs `[browser]`):
  ```bash
  python examples/render_report_ui.py reports/demo.json -o reports/demo_ui
  # → reports/demo_ui.svg, .html, and .png
  ```

### A7. Debug ORTHRUS with breakpoints
`python -m orthrus.main` is runnable, so you can debug the CLI directly. Create
**`.vscode/launch.json`** with:

```jsonc
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "orthrus scan (practice target)",
      "type": "debugpy",
      "request": "launch",
      "module": "orthrus.main",
      "args": [
        "--no-banner", "scan",
        "-t", "http://127.0.0.1:8731",
        "--aggressive", "--no-browser",
        "-o", "reports/debug.json", "--format", "json"
      ],
      "console": "integratedTerminal",
      "justMyCode": false
    }
  ]
}
```

Set a breakpoint (e.g. in a scanner under `orthrus/scanners/`), make sure the
practice target from **A5** is running, then press **F5**. `justMyCode: false`
lets you step into library calls too.

> `.vscode/` is gitignored in this repo, so your `launch.json` stays local - that's expected and won't be committed.

### A8. Run tests & lint from VS Code
The project is pre-configured (`pyproject.toml`: `pytest` with `asyncio_mode=auto`, `ruff`).

- **Test Explorer:** open the **Testing** flask icon in the sidebar → tests are auto-discovered → run/debug individual tests.
- **Terminal equivalents:**
  ```bash
  pytest -q              # full offline suite
  ruff check orthrus tests
  mypy orthrus
  ```

The suite is offline and deterministic - it never touches the network.

### A9. Full end-to-end scan of a site you own
Once you're comfortable, point it at a system you **own** or are **authorized** to
test, and always pass an **explicit scope**. `orthrus scan` runs all four phases
(recon → scan → exploit-confirm → report) in one command:

```bash
# 1) Preview the scope + plan first - sends NO traffic
orthrus scan -t https://yoursite.com --scope "yoursite.com,*.yoursite.com" --dry-run

# 2) Run the full pipeline with gentle, live-site-friendly settings
orthrus scan -t https://yoursite.com \
  --scope "yoursite.com,*.yoursite.com" \
  --rate-limit 10 \
  --crawl-depth 3 --max-pages 200 \
  --exclude-paths "/logout,/admin/delete/.*" \
  -o reports/yoursite.html --format html --template technical

# 3) Export more formats from the same stored scan (no re-scan)
orthrus scans                                                          # copy the scan id
orthrus report --scan-id <id> --format pdf   --template executive -o reports/yoursite_exec
orthrus report --scan-id <id> --format sarif -o reports/yoursite
```

Add `--aggressive` for time-based blind + race-condition tests, `--auth-cookie`
for authenticated areas, or `--proxy http://127.0.0.1:8080` to watch traffic in
Burp/ZAP. See the README's
[recommended workflow](../README.md#full-end-to-end-scan-of-a-site-you-own-recommended-workflow)
for the full set of options.

### VS Code troubleshooting
| Symptom | Fix |
|---|---|
| `orthrus: command not found` | The venv isn't active / selected. Re-activate it, or run `python -m orthrus.main …`. |
| `Activate.ps1 cannot be loaded` (PowerShell) | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`, then activate again. |
| Tests not discovered | Select the `.venv` interpreter (A2), then `Ctrl/Cmd+Shift+P` → **Python: Configure Tests** → **pytest** → `tests`. |
| `dom-xss`/`stored-xss` skipped | Install `[browser]` and run `playwright install chromium`. |
| `jwt`/`tls` scanner skipped | Install `[scanners]`. |

---

## Part B - Google Colab

Colab gives you a free, clean **Linux** box with Python already installed - no
local setup. A few things to know going in:

- **Sessions are ephemeral.** Installs and files vanish when the runtime resets;
  download any report you want to keep (shown below) or mount Google Drive.
- **No second terminal and no GUI.** We start the practice target as a
  **background process** and read the report inline.
- **We drive ORTHRUS through the shell (`!orthrus …` / `subprocess`)**, not by
  importing it into a cell. That's deliberate: a Colab notebook already runs its
  own asyncio event loop, and ORTHRUS starts its own - running it as a
  subprocess keeps the two from colliding (no `nest_asyncio` hacks needed).
- Colab's Python (currently 3.12) satisfies the **≥3.11** requirement - confirm with `!python --version`.

### Option 1 - One-click notebook (recommended)
The repo ships a ready-to-run notebook. Open it directly in Colab:

**→ https://colab.research.google.com/github/ankitjha67/orthrus/blob/main/examples/orthrus_colab.ipynb**

Then **Runtime → Run all**. It installs ORTHRUS, starts the bundled practice
target, runs a full scan, and prints the findings. Every cell is commented.

### Option 2 - Build it cell by cell
Prefer to type it yourself (or adapt it)? Paste each block into its own Colab cell.

**Cell 1 - install ORTHRUS** (clone + lean core):
```python
import os
REPO = "/content/orthrus"
if not os.path.isdir(REPO):
    !git clone --depth 1 https://github.com/ankitjha67/orthrus.git {REPO}
os.chdir(REPO)
!pip -q install -e .
print("\n✅ installed -", end=" ")
!python --version
!orthrus --version
```

**Cell 2 - environment readiness** (no network; safe):
```python
!orthrus --no-banner doctor
```

**Cell 3 - start the bundled, authorized practice target** (background, 127.0.0.1 only):
```python
import subprocess, sys, socket, time

PORT = 8731
target = subprocess.Popen(
    [sys.executable, "tests/integration/reflecting_target.py", str(PORT)],
    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
)
for _ in range(50):                                   # wait until it accepts connections
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
            print(f"✅ practice target listening on http://127.0.0.1:{PORT} (pid {target.pid})")
            break
    except OSError:
        time.sleep(0.2)
else:
    raise RuntimeError("practice target did not start")
```

**Cell 4 - run the full scan** (recon → scan → confirm → report):
```python
import subprocess
os.makedirs("reports", exist_ok=True)
cmd = [
    "orthrus", "--no-banner", "scan",
    "-t", "http://127.0.0.1:8731",
    "--aggressive", "--no-browser",          # browser extras aren't installed by default in Colab
    "--crawl-depth", "3", "--max-pages", "50",
    "-o", "reports/colab.json", "--format", "json",
]
print("running:", " ".join(cmd), "\n")
subprocess.run(cmd, check=True)
```

**Cell 5 - read the results**:
```python
import json, collections
data = json.load(open("reports/colab.json"))
s = data["summary"]
print(f"total findings: {s['total']}   confirmed: {s['confirmed']}")
print("by severity:", dict(s["counts"]))
print("-" * 70)
for f in sorted(data["findings"], key=lambda x: x["severity"]):
    print(f"[{f['severity']:<8}] {f['confidence']:<10} {f['vuln_type']:<22} {f['url']}")
```

**Cell 6 (optional) - render the themed report UI as a PNG**:
```python
!pip -q install -e ".[browser]"
!playwright install --with-deps chromium
!python examples/render_report_ui.py reports/colab.json -o reports/colab_ui
from IPython.display import Image
Image("reports/colab_ui.png")
```

**Cell 7 (optional) - download the report**:
```python
from google.colab import files
files.download("reports/colab.json")
```

**Cell 8 (optional) - stop the practice target**:
```python
target.terminate()
print("stopped practice target")
```

### Scanning your *own* authorized target from Colab
Skip the practice-target cells and scan a system you're permitted to test, with
an **explicit scope**. Note Colab runs from a Google datacenter IP - only do
this where that source is authorized:

```python
import subprocess
subprocess.run([
    "orthrus", "--no-banner", "scan",
    "-t", "https://app.you-own.com",
    "--scope", "*.you-own.com",
    "--no-browser",
    "-o", "reports/engagement.json", "--format", "json",
], check=True)
```

### Persisting reports across sessions (optional)
Colab wipes the runtime on reset. To keep reports, mount Google Drive and write there:
```python
from google.colab import drive
drive.mount("/content/drive")
# then use -o /content/drive/MyDrive/orthrus/report.json
```

### Colab troubleshooting
| Symptom | Fix |
|---|---|
| `pip` warns "restart runtime" after install | Usually unnecessary because we call `orthrus` as a subprocess (fresh imports). If a scan errors oddly, **Runtime → Restart session** and re-run from Cell 1. |
| Scan can't reach `127.0.0.1:8731` | Re-run Cell 3; the readiness loop must print "listening" before you run Cell 4. |
| Browser/PDF render fails | `!playwright install --with-deps chromium` needs the `--with-deps` flag in Colab to pull system libraries. |
| Everything disappeared | The session reset - installs/files are ephemeral. Re-run from Cell 1, and use Drive (above) to persist. |

---

## Command cheat-sheet (both environments)

```bash
orthrus --help                       # global help
orthrus scan --help                  # every scan flag
orthrus doctor                       # capability/readiness check (no network)
orthrus modules                      # list scanner/exploit/recon modules
orthrus recon  -t URL -o recon.json  # reconnaissance only
orthrus scan   -t URL -o report.json # full pipeline (recon→scan→confirm→report)
orthrus report --scan-id ID --format pdf --template executive -o exec
```

Formats: `json`, `csv`, `html`, `pdf`, `md`, `sarif`. Templates: `executive`,
`technical`, `compliance`. Add `--min-severity high` to filter, `--fail-on high`
for CI exit codes.

**Remember:** authorized targets only. When in doubt, scan the bundled practice
target or a self-hosted lab - never a system you don't have written permission to test.
