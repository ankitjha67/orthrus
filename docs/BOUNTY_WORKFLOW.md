# ORTHRUS bug-bounty workflow (VS Code, end to end)

From "I have some raw output" to **submission-ready HackerOne reports**, with an
LLM writing the narrative. Every command runs from the ORTHRUS repo folder.

> Test only assets you are authorized to test, from your own attributed
> environment, within the program's rules and rate limits.

---

## 0. One-time: open ORTHRUS in VS Code

1. **File > Open Folder** -> the ORTHRUS repo.
2. **Ctrl+Shift+P** -> `Python: Select Interpreter` -> pick the project's
   `.venv` (`.venv\Scripts\python.exe`).
3. Open a terminal: **Ctrl+`** (backtick). It activates the venv automatically.
4. Install the CLI once (editable, so `orthrus` is on PATH):
   ```powershell
   pip install -e ".[scanners,reporting,api]"
   orthrus --version
   ```
   If `orthrus` isn't found, use `python -m orthrus.main` in place of `orthrus`
   everywhere below.

---

## 1. Add your LLM API key (for the AI report)

ORTHRUS reads these environment variables. Set them in the **integrated terminal**
at the start of a session (most reliable), or persist them (see below).

### NVIDIA NIM (your key)

```powershell
$env:ORTHRUS_LLM_API_KEY  = "nvapi-YOUR-KEY"
$env:ORTHRUS_LLM_BASE_URL = "https://integrate.api.nvidia.com/v1"
$env:ORTHRUS_LLM_TIMEOUT  = "300"     # big hosted models are slow/cold
```

Then select the model with `--llm openai-compatible:<model-id>`:
- **Fast, reliable full runs:** `openai-compatible:meta/llama-3.1-8b-instruct` (~1s/call).
- Big models (`z-ai/glm-5.2`, `meta/llama-3.3-70b-instruct`) are congested on the
  free tier (slow, occasional 504); use them off-peak with the 300s timeout.

### Other providers (same knobs)

| Provider | Env | `--llm` spec |
|---|---|---|
| Anthropic | `ORTHRUS_LLM_API_KEY` (or `ANTHROPIC_API_KEY`) | `anthropic:claude-sonnet-5` |
| OpenAI | `ORTHRUS_LLM_API_KEY` (or `OPENAI_API_KEY`) | `openai:gpt-4o` |
| Local Ollama (free, offline) | none | `ollama:llama3.1` |

### Persist the key (optional)

- **PowerShell profile:** `notepad $PROFILE`, add the three `$env:...` lines.
- **VS Code debugger:** copy `.env.example` to `.env` (gitignored) and fill it in;
  the Python extension loads `.env` for debug runs.

### Verify it works before a real run

```powershell
# no model call - just proves the report assembles:
orthrus ai-report --scan-id <your-scan-id> --dry-run --format md -o test.md
# a tiny real call - proves the key + endpoint are wired:
orthrus ai-report --scan-id <your-scan-id> --llm openai-compatible:meta/llama-3.1-8b-instruct \
  --max-detailed 1 --format md -o test.md
```

Secrets in evidence are **redacted before anything leaves your host**.

---

## 2. Get your raw output

Pick whichever matches how you tested. All three feed the same pipeline.

### Path A - you ran an ORTHRUS scan yourself
```powershell
orthrus bounty --program 1win --platform hackerone -o 1win-run/
```
Gives you a **scan id** (also in the DB), a ranked `findings.json`, and per-bug
reports. Skip to step 4 (you already have findings).

### Path B - you tested manually through a proxy
Use **ORTHRUS's own intercepting proxy** (no Burp/Caido needed) or export from them:

```powershell
# one-time: export + install the ORTHRUS CA in your browser/OS trust store
orthrus proxy --export-ca orthrus-ca.crt
# then run the MITM proxy (HTTPS bodies captured for in-scope hosts) into a scan:
orthrus scan -t https://1win.com --scope 1win.com --dry-run --scan-id 1win   # make the scan
orthrus proxy --intercept-tls --scope 1win.com --scan-id 1win                # browse via 127.0.0.1:8080
```

Or export from Burp/Caido and import the file (Path B, step 3):
- **Burp:** Proxy > HTTP history > select items > right-click > *Save items* (XML).
- **Caido:** export the request list as JSON.
- **Browser only:** DevTools > Network > *Save all as HAR*.

### Path C - you already have a `findings.json` or a scan DB
Use them directly (steps 4-6).

---

## 3. Import your traffic into the operator graph (Path B)

Folds the hosts + routes you exercised into a program (out-of-scope hosts are
refused automatically):

```powershell
orthrus import-traffic history.har  --program 1win   # auto-detects burp/caido/har
# create the program on first import if it doesn't exist yet:
orthrus import-traffic burp-items.xml --program 1win --authorization https://hackerone.com/1win_com --in-scope 1win.com
```

Ask ORTHRUS what to do next, grounded in what you imported:
```powershell
orthrus plan --program 1win
```

---

## 4. Turn traffic/assets into findings, then dedup + correlate + rank

```powershell
# scan the imported/known in-scope assets -> promote deduped, priority-ranked
# findings into the graph, and auto-correlate attack chains:
orthrus program-scan --program 1win

# the triage queue, priority-first:
orthrus program-findings --program 1win
orthrus program-findings --program 1win --status new --json   # machine-readable

# the correlated kill-chains (e.g. "jwt enables idor"):
orthrus program-chains --program 1win
```

Already have a `findings.json` / scan id from Path A? It's already deduped and
ranked - go straight to the writeup.

---

## 5. AI writeup (LLM narrative, grounded in evidence)

```powershell
orthrus ai-report --scan-id <scan-id> \
  --llm openai-compatible:meta/llama-3.1-8b-instruct \
  --min-severity medium --format md -o 1win-consultant.md
# styled HTML or PDF instead:
#   --format html -o 1win-consultant.html
#   --format pdf  -o 1win-consultant.pdf
```

The model writes exec summary / impact / remediation **around** the fixed findings
and their verbatim evidence - it cannot invent a vulnerability.

---

## 6. Submission-ready HackerOne reports

```powershell
# per-bug reports shaped for HackerOne's form, deduped, confidence floor 'firm':
orthrus bounty-report --program 1win --platform hackerone --min-confidence firm -o 1win-h1/
```

You get one clean Markdown file per bug (title, CWE, severity, repro with the
request, impact) plus an index. Paste into the H1 submission form, attach evidence,
submit.

---

## 7. Track what you filed / earned

```powershell
orthrus submission --program 1win --title "IDOR in /account voucher" --status filed --severity high
orthrus submissions --program 1win     # earnings roll-up
orthrus bounty-status                   # one-view cockpit
```

---

## Quick reference

| Goal | Command |
|---|---|
| Scope briefing from the CSV | `orthrus scope-report scope.csv -o brief.md` |
| Import Burp/Caido/HAR | `orthrus import-traffic FILE --program 1win` |
| Scan + promote + correlate | `orthrus program-scan --program 1win` |
| Triage queue | `orthrus program-findings --program 1win` |
| Attack chains | `orthrus program-chains --program 1win` |
| What to do next | `orthrus plan --program 1win` |
| AI consultant report | `orthrus ai-report --scan-id ID --llm openai-compatible:meta/llama-3.1-8b-instruct -o r.md` |
| H1 submission reports | `orthrus bounty-report --program 1win --platform hackerone -o h1/` |
| Fuzz a request (Intruder) | `orthrus intruder --request-file req.txt --payloads words.txt --scope <host> --match SQL` |
| Intercept HTTPS (MITM) | `orthrus proxy --intercept-tls --scope <host> --scan-id <id>` (export/install the CA first) |
| Match & Replace | `orthrus proxy --intercept-tls --rewrite rules.json --scope <host>` |
| Repeater (resend + tweak) | `orthrus replay --request-file req.txt --scope <host>` |
| The cockpit UI (incl. Workbench: Repeater + Intruder) | `orthrus serve --cockpit` -> http://127.0.0.1:8000/cockpit |

## Intruder - fuzzing a request

Mark injection points with `§...§` in a saved raw request, then attack them:

```powershell
# mark the id: "GET /account?id=§1§ HTTP/1.1 ..."  saved as req.txt
orthrus intruder --request-file req.txt --payloads ids.txt --mode sniper `
  --scope 1win.com --match "error"
```

- **Modes:** `sniper` (one position at a time), `batteringram` (same payload everywhere),
  `pitchfork` (one list per position, lockstep), `clusterbomb` (every combination).
- `--payloads` takes a file (one per line) or an inline `a,b,c`; repeat it for
  pitchfork/clusterbomb (one list per position).
- Responses are ranked so the **anomaly** (a different status/length) and any
  `--match` hits float to the top. Every request is scope-checked before it is sent.
