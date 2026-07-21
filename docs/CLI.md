# ORTHRUS CLI reference

_Auto-generated from the Click command tree — regenerate with_ `python scripts/gen_cli_docs.py`_._

## `orthrus`

```text
Usage: orthrus [OPTIONS] COMMAND [ARGS]...

  ORTHRUS - automated vulnerability discovery & exploitation confirmation.

  For authorized security testing only.

Options:
  --version    Show the version and exit.
  --no-banner  Suppress the startup banner (also via ORTHRUS_NO_BANNER=1).
  --help       Show this message and exit.

Commands:
  agent             Autonomous orchestrator: an LLM plans which...
  ai-report         Generate a Big-Four-grade consultant report —...
  audit             Show or verify the tamper-evident bug-bounty audit log.
  benchmark         Measure detection accuracy against a...
  bounty            Run an authorized bug-bounty campaign: scan every...
  bounty-assets     Show the live in-scope asset inventory recorded for a...
  bounty-report     Re-render a saved program's last campaign - no...
  bounty-status     One-view operator dashboard: programs, submissions,...
  chains            Correlate a scan's findings into attack paths...
  cloud             Assess cloud security posture (CSPM/IAM) from a...
  completion        Output a tab-completion script for SHELL (bash, zsh,...
  copilot           Ask a copilot grounded in YOUR notes + submissions...
  cost              Show the cost ledger (LLM spend auto-recorded by the...
  diff              Compare two scans: what's NEW, FIXED, or STILL PRESENT.
  doctor            Check which optional integrations are available in...
  exploit           Run exploitation confirmation against a previous...
  finding           Manage a stored finding's triage lifecycle (status /...
  findings          Show a stored scan's findings as a triage table (or...
  graph             Collapse a scan's findings into the few reachable...
  hosts             Gather and list the host footprint for a TARGET (or a...
  iac               Audit Infrastructure-as-Code for misconfigurations...
  import-traffic    Import a Burp / Caido / HAR proxy history into a...
  mcp               Run the ORTHRUS MCP server (stdio) — expose...
  migrate           Promote existing v0.1 scans/findings into the v2.0...
  modules           List scanner and exploit-confirmation modules, or...
  monitor           Re-scan a TARGET and report drift vs the previous run.
  note              Save an operator note (methodology, per-program tips,...
  notes             List or search operator notes.
  notify            Push a scan's high-severity findings to Slack and/or...
  panic             Emergency kill switch: halt ALL outbound requests +...
  patch             Generate concrete remediation patches (config/code)...
  plan              Suggest the next steps for a program, grounded in its...
  program-findings  List a program's operator-graph findings (the triage...
  program-policy    Set a program's traffic policy: a rate ceiling and an...
  program-scan      Scan a program's live in-scope assets → promote...
  programs          List saved bug-bounty programs (scope, authorization,...
  proxy             Run a scope-aware capturing proxy to feed the scanner...
  recon             Run reconnaissance only.
  recon-run         Run continuous recon for a program: enumerate its...
  recon-watch       Continuously re-run recon for a program, alerting on...
  replay            Resend a recorded request with optional tweaks — the...
  report            Generate a report from an existing scan.
  runbook           Consolidated remediation runbook — the few fixes that...
  scan              Run the full pipeline: recon -> scan -> exploit ->...
  scans             List previous scans (id, status, phase, findings) for...
  serve             Run the ORTHRUS REST API (scans/findings +...
  submission        Record or update a bug-bounty submission (status,...
  submissions       List tracked submissions and roll up earnings.
  suppress          Add a mute rule so known-noise findings stay out of a...
  suppressions      List (or --remove) a program's mute rules.
  surface           Render a scan's recon (hosts / ports / technologies /...
  team              Manage team members + per-program roles on the...
  triage            Deduplicate + cluster a scan's findings into distinct...
  update            Refresh threat-intel feeds (CISA KEV + EPSS) used to...
```

**Commands:** [`agent`](#orthrus-agent) · [`ai-report`](#orthrus-ai-report) · [`audit`](#orthrus-audit) · [`benchmark`](#orthrus-benchmark) · [`bounty`](#orthrus-bounty) · [`bounty-assets`](#orthrus-bounty-assets) · [`bounty-report`](#orthrus-bounty-report) · [`bounty-status`](#orthrus-bounty-status) · [`chains`](#orthrus-chains) · [`cloud`](#orthrus-cloud) · [`completion`](#orthrus-completion) · [`copilot`](#orthrus-copilot) · [`cost`](#orthrus-cost) · [`diff`](#orthrus-diff) · [`doctor`](#orthrus-doctor) · [`exploit`](#orthrus-exploit) · [`finding`](#orthrus-finding) · [`findings`](#orthrus-findings) · [`graph`](#orthrus-graph) · [`hosts`](#orthrus-hosts) · [`iac`](#orthrus-iac) · [`import-traffic`](#orthrus-import-traffic) · [`mcp`](#orthrus-mcp) · [`migrate`](#orthrus-migrate) · [`modules`](#orthrus-modules) · [`monitor`](#orthrus-monitor) · [`note`](#orthrus-note) · [`notes`](#orthrus-notes) · [`notify`](#orthrus-notify) · [`panic`](#orthrus-panic) · [`patch`](#orthrus-patch) · [`plan`](#orthrus-plan) · [`program-findings`](#orthrus-program-findings) · [`program-policy`](#orthrus-program-policy) · [`program-scan`](#orthrus-program-scan) · [`programs`](#orthrus-programs) · [`proxy`](#orthrus-proxy) · [`recon`](#orthrus-recon) · [`recon-run`](#orthrus-recon-run) · [`recon-watch`](#orthrus-recon-watch) · [`replay`](#orthrus-replay) · [`report`](#orthrus-report) · [`runbook`](#orthrus-runbook) · [`scan`](#orthrus-scan) · [`scans`](#orthrus-scans) · [`serve`](#orthrus-serve) · [`submission`](#orthrus-submission) · [`submissions`](#orthrus-submissions) · [`suppress`](#orthrus-suppress) · [`suppressions`](#orthrus-suppressions) · [`surface`](#orthrus-surface) · [`team`](#orthrus-team) · [`triage`](#orthrus-triage) · [`update`](#orthrus-update)

## `orthrus agent`

```text
Usage: orthrus agent [OPTIONS]

  Autonomous orchestrator: an LLM plans which scope-enforced scanners to run,
  in a loop.

  The agent reasons over the target and findings-so-far and picks the next
  batch of ORTHRUS's own scanners to run, up to --max-steps. Its action space
  is a hard allow-list of registered modules — no shells, no arbitrary code —
  and every request still passes the deny-by-default scope check and non-
  destructive doctrine. Use --dry-run to see the plan without running
  anything.

Options:
  -t, --target TEXT               Target URL (a host you own / are authorized
                                  to test).  [required]
  --scope TEXT                    Scope: wildcard domains / CIDR ranges.
  --aggressiveness [passive|normal|aggressive]
                                  Caps which scanners the agent may choose.
  --max-steps INTEGER             Max plan→execute→re-plan iterations.
  --dry-run                       Show the plan; execute nothing.
  --llm / --no-llm                Plan with an Anthropic model (needs API
                                  key); else a deterministic policy.
  --model TEXT                    LLM model id (with --llm).
  --crawl-depth INTEGER           Crawl depth per executed step.
  --timeout FLOAT                 HTTP request timeout (s).
  --exclude-paths TEXT            Comma-separated regex paths to exclude
                                  (scope).
  --json                          Emit the run report as JSON.
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus ai-report`

```text
Usage: orthrus ai-report [OPTIONS]

  Generate a Big-Four-grade consultant report — deterministic evidence + AI
  narrative.

  Every finding, CVSS score, and recorded request/response is rendered
  verbatim; a language model writes the consultant prose around those facts
  (executive summary, per-finding impact/likelihood/exploitation/remediation,
  attack-chain stories, remediation roadmap). The model can be local (ollama)
  or any market model. --dry-run shows the full structure and evidence without
  any model call.

Options:
  --scan-id TEXT          Scan identifier to report on.  [required]
  --llm TEXT              Model spec 'provider:model' — anthropic / openai /
                          openai-compatible / ollama (e.g. 'ollama:llama3.1',
                          'openai:gpt-4o'). Keys/base-url from env.
  --model TEXT            Override the model id.
  -o, --output TEXT       Output file (extension set by --format).
  --format [md|html|pdf]  Deliverable format. html/pdf render a styled Big-
                          Four document; pdf reuses the Chromium pipeline
                          (needs the [browser] extra).
  --group / --no-group    Group like findings (same type + title) into one
                          entry with an affected-instances table. On by
                          default.
  --min-severity TEXT     Only include findings at/above this severity.
  --max-detailed INTEGER  Max findings given a full AI narrative.
  --temperature FLOAT     Model temperature.
  --dry-run               Assemble the full report scaffold + recorded
                          evidence with NO model calls.
  -v, --verbose TEXT      Log level.
  --help                  Show this message and exit.
```

## `orthrus audit`

```text
Usage: orthrus audit [OPTIONS]

  Show or verify the tamper-evident bug-bounty audit log.

Options:
  --verify             Check the hash-chain for tampering and exit.
  -n, --limit INTEGER  How many recent entries to show.  [default: 20]
  --help               Show this message and exit.
```

## `orthrus benchmark`

```text
Usage: orthrus benchmark [OPTIONS]

  Measure detection accuracy against a known-vulnerability ground truth.

  Scans a target you own, then scores the findings against an enumerated
  ground-truth file: detection rate (did we catch the known bugs?) and a
  false-positive proxy (did we report bugs that aren't in the truth?).

Options:
  -t, --target TEXT         Target URL (a host you own / are authorized to
                            test).  [required]
  --truth TEXT              Ground-truth file path, or a bundled name (e.g.
                            'reflecting-target').  [required]
  --scope TEXT              Scope: wildcard domains / CIDR ranges.
  --modules TEXT            Comma-separated scanner modules.
  --aggressive              Enable aggressive scanning (some classes need it).
  --confirm / --no-confirm  Run exploitation confirmation before scoring.
  --browser / --no-browser  Use headless browser (DOM/stored XSS).
  --rate-limit FLOAT        Max requests/sec per domain.
  --timeout FLOAT           HTTP request timeout (s).
  --exclude-paths TEXT      Comma-separated regex paths to exclude.
  -o, --output TEXT         Write the benchmark result as JSON to this path.
  -v, --verbose TEXT        Log level.
  --help                    Show this message and exit.
```

## `orthrus bounty`

```text
Usage: orthrus bounty [OPTIONS]

  Run an authorized bug-bounty campaign: scan every in-scope asset with all
  scanners, confirm the findings, and write submission-ready per-bug reports.

  Requires an explicit program scope (--scope-file or --in-scope) — ORTHRUS is
  deny-by-default and will not scan without one. Out-of-scope entries are
  enforced and never touched. Authorized programs only.

Options:
  --program NAME                  Save/load this engagement under a name:
                                  persists scope + authorization and the
                                  campaign history, so you can re-run a
                                  program by name (see 'orthrus programs').
  --scope-file FILE               Program scope file: in-scope assets, one per
                                  line; a '!' prefix marks an out-of-scope
                                  exclusion; '#' comments.
  --in-scope ASSET                Add an in-scope asset (domain / *.wildcard /
                                  URL / CIDR). Repeatable.
  --out-scope ASSET               Add an out-of-scope exclusion. Repeatable.
  --authorization SOURCE          Proof you're authorized: a program URL
                                  (hackerone.com/…, bugcrowd.com/…),
                                  'signed:<file>', 'direct:<note>', or 'self-
                                  owned-lab'. Required for public scopes.
  --i-am-authorized HOST          Attest written authorization for a high-
                                  sensitivity host (gov/mil/edu/health) so it
                                  isn't refused. Repeatable; name the exact
                                  host.
  --enumerate / --no-enumerate    Discover live in-scope subdomains (crt.sh +
                                  DNS) and scan them too, not just the seeds
                                  you listed. In-scope, non-excluded, non-
                                  sensitive hosts only.  [default: enumerate]
  --min-confidence [confirmed|firm|tentative]
                                  Only report bugs at/above this confidence
                                  (keeps triager noise down).  [default: firm]
  --platform [generic|hackerone|bugcrowd|intigriti|yeswehack|immunefi]
                                  Shape each per-bug report for this
                                  platform's submission form.  [default:
                                  generic]
  --notify-slack WEBHOOK          Post a campaign summary to this Slack
                                  incoming webhook (or set
                                  ORTHRUS_SLACK_WEBHOOK).
  --tools NAMES                   Also run external-tool adapters per asset
                                  (comma-separated, or 'all'): nuclei, dalfox,
                                  testssl, ffuf. Needs the binaries on PATH.
  --aggressive                    Enable aggressive scanning.
  --browser / --no-browser        Use a headless browser (DOM/stored XSS).
  --no-exploit                    Skip the exploitation-confirmation phase.
  --callback TEXT                 Advertise host for the local OOB listener
                                  (SSRF/XXE/deserialization confirmation).
  --interactsh                    Use a real Interactsh OOB collaborator for
                                  blind/OOB confirmation.
  --rate-limit FLOAT              Max requests/sec per host.  [default: 20.0]
  --timeout FLOAT                 HTTP request timeout (s).  [default: 30.0]
  --crawl-depth INTEGER           [default: 10]
  --max-pages INTEGER             [default: 2000]
  --threads INTEGER               [default: 10]
  -o, --output TEXT               Directory for the submission-ready reports.
                                  [default: bounty-report]
  --dry-run                       Resolve and print the scope + seeds, then
                                  stop (no requests sent).
  --help                          Show this message and exit.
```

## `orthrus bounty-assets`

```text
Usage: orthrus bounty-assets [OPTIONS]

  Show the live in-scope asset inventory recorded for a program.

  Populated by `orthrus bounty --program NAME --enumerate`, which snapshots
  the live in-scope hosts each run and reports which are NEW since the last
  one.

Options:
  --program TEXT  Program name (as saved).  [required]
  --json          Emit the asset inventory as JSON.
  --help          Show this message and exit.
```

## `orthrus bounty-report`

```text
Usage: orthrus bounty-report [OPTIONS]

  Re-render a saved program's last campaign - no re-scanning.

  Regenerate the submission reports from the findings already stored for a
  program's past scans, e.g. in a different --platform format, applying the
  program's current mute rules and flagging cross-run duplicates.

Options:
  --program TEXT                  Saved program to re-render.  [required]
  --platform [generic|hackerone|bugcrowd|intigriti|yeswehack|immunefi]
                                  Shape reports for this platform's submission
                                  form.
  --min-confidence [confirmed|firm|tentative]
                                  Report floor.
  -o, --output TEXT               Output directory.
  --help                          Show this message and exit.
```

## `orthrus bounty-status`

```text
Usage: orthrus bounty-status [OPTIONS]

  One-view operator dashboard: programs, submissions, earnings, audit
  integrity.

Options:
  --json  Emit the full status as JSON (for scripting).
  --help  Show this message and exit.
```

## `orthrus chains`

```text
Usage: orthrus chains [OPTIONS]

  Correlate a scan's findings into attack paths (kill-chains).

  A flat finding list hides impact: one SSRF and one exposed Redis are two
  mediums — together they're RCE on the internal network. This matches the
  findings against a catalog of known attack chains and shows the paths an
  attacker would actually walk, each with an escalated severity and an impact
  narrative, prioritised above the raw list.

Options:
  --scan-id TEXT      Scan identifier from a previous run.  [required]
  --json              Emit the attack paths as JSON (stdout).
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus cloud`

```text
Usage: orthrus cloud [OPTIONS] [SNAPSHOT]

  Assess cloud security posture (CSPM/IAM) from a snapshot or read-only
  collection.

  Consumes a normalized inventory JSON (SNAPSHOT) — or, with --live, collects
  one read-only from the provider using your own credentials — and reports
  public / unencrypted / over-privileged resources plus the CRITICAL *toxic
  combinations* an attacker would chain (internet-reachable workload +
  privileged role, admin user without MFA, PassRole escalation). Read-only: it
  never modifies anything.

Options:
  --provider [aws]                Cloud provider (for --live).
  --live                          Collect a read-only inventory from the
                                  provider (needs credentials + [cloud]
                                  extra).
  --regions TEXT                  Comma-separated regions for --live
                                  collection.
  --toxic-only                    Show only the correlated toxic-combination
                                  paths.
  -o, --output TEXT               Write findings as JSON to this path.
  --fail-on [critical|high|medium|low|info]
                                  Exit non-zero if a finding at/above this
                                  severity is found (for CI).
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus completion`

```text
Usage: orthrus completion [OPTIONS] {bash|zsh|fish}

  Output a tab-completion script for SHELL (bash, zsh, or fish).

  The script is written to stdout so it can be sourced or saved, e.g.:

    eval "$(orthrus completion bash)"        # current shell
    orthrus completion bash >> ~/.bashrc     # persist (bash)
    orthrus completion zsh  >> ~/.zshrc      # persist (zsh)
    orthrus completion fish > ~/.config/fish/completions/orthrus.fish

Options:
  --help  Show this message and exit.
```

## `orthrus copilot`

```text
Usage: orthrus copilot [OPTIONS] QUERY...

  Ask a copilot grounded in YOUR notes + submissions (never invents findings).

Options:
  --llm PROVIDER:MODEL  Ground the answer with a model (e.g. ollama:llama3.1).
                        Omit for raw snippets.
  -k, --top INTEGER     Snippets to retrieve.  [default: 5]
  --help                Show this message and exit.
```

## `orthrus cost`

```text
Usage: orthrus cost [OPTIONS]

  Show the cost ledger (LLM spend auto-recorded by the copilot, plus anything
  you log).

Options:
  --program TEXT  Filter to one program.
  --help          Show this message and exit.
```

## `orthrus diff`

```text
Usage: orthrus diff [OPTIONS]

  Compare two scans: what's NEW, FIXED, or STILL PRESENT.

  A read-only, network-free retest view. Findings are matched across the two
  scans by type + URL + parameter, so you can confirm a fix landed (FIXED),
  catch regressions (NEW), and see what still needs work (STILL PRESENT). Pair
  --fail-on-new with a retest pipeline to fail the build on any new bug.

Options:
  --base TEXT                     Baseline scan id (the 'before').  [required]
  --against TEXT                  Newer scan id (the 'after').  [required]
  --severity [critical|high|medium|low|info]
                                  Only consider findings at or above this
                                  severity.
  --json                          Emit the diff as JSON (stdout).
  --fail-on-new                   Exit 3 if any NEW finding appears (retest/CI
                                  regression gate).
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus doctor`

```text
Usage: orthrus doctor [OPTIONS]

  Check which optional integrations are available in this environment.

  A read-only, network-free environment probe: it reports the active vs.
  missing optional capabilities (browser engine, nmap, distributed broker,
  Postgres, ...) and how to enable each. Always exits 0.

Options:
  --json  Emit diagnostics as JSON (stdout).
  --help  Show this message and exit.
```

## `orthrus exploit`

```text
Usage: orthrus exploit [OPTIONS]

  Run exploitation confirmation against a previous scan's findings.

Options:
  --scan-id TEXT      Scan identifier from a previous run.  [required]
  --confirm-all       Attempt confirmation of all findings.
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus finding`

```text
Usage: orthrus finding [OPTIONS] COMMAND [ARGS]...

  Manage a stored finding's triage lifecycle (status / ownership).

Options:
  --help  Show this message and exit.

Commands:
  assign  Assign a finding to an OWNER (use '-' to clear the assignment).
  status  Set a finding's triage STATE...
```

## `orthrus findings`

```text
Usage: orthrus findings [OPTIONS]

  Show a stored scan's findings as a triage table (or JSON).

  A read-only, network-free view of what a previous scan found — the quick
  triage list (severity, type, where, how sure) without regenerating a full
  report. Use --severity to focus on the high-risk end and --json to pipe the
  findings into other tools (stdout is reserved for that JSON; chrome is
  stderr).

Options:
  --scan-id TEXT                  Scan identifier from a previous run.
                                  [required]
  --severity [critical|high|medium|low|info]
                                  Only show findings at or above this
                                  severity.
  --json                          Emit findings as JSON (stdout).
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus graph`

```text
Usage: orthrus graph [OPTIONS]

  Collapse a scan's findings into the few reachable attack paths.

  Where `chains` matches each catalog rule independently, this builds a
  reachability graph and *merges* rules that share a finding into maximal
  kill-chains — e.g. LFI → exposed-secret → JWT-forgery becomes one three-step
  path. Reports how many raw findings collapse onto how few reachable paths.

Options:
  --scan-id TEXT      Scan identifier from a previous run.  [required]
  --json              Emit the attack graph as JSON (stdout).
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus hosts`

```text
Usage: orthrus hosts [OPTIONS] [TARGET]

  Gather and list the host footprint for a TARGET (or a stored scan).

  Casts a passive net — Certificate Transparency, reverse-IP / co-hosting, a
  /24 reverse-DNS sweep, and Wayback — and folds the results into one
  deduplicated inventory. In-scope hosts are listed first; co-hosted hosts
  that fall outside scope are shown (flagged) for situational awareness but
  are never scanned. Use --scan-id to instead list the hosts a prior scan
  stored.

Options:
  --scope TEXT          Scope token(s); defaults to the target host
                        (+subdomains).
  --scan-id TEXT        List hosts from a stored scan instead of gathering
                        live.
  --no-reverse-ip       Skip reverse-IP / co-hosting lookup.
  --no-netblock         Skip the /24 reverse-DNS sweep.
  --no-ct               Skip Certificate Transparency (crt.sh).
  --no-wayback          Skip Wayback Machine hostnames.
  --in-scope-only       Hide co-hosted / out-of-scope hosts.
  --json                Emit the host inventory as JSON (stdout).
  --csv TEXT            Write the host inventory to a CSV file.
  --exclude-paths TEXT  Comma-separated regex paths to exclude (scope).
  -v, --verbose TEXT    Log level.
  --help                Show this message and exit.
```

## `orthrus iac`

```text
Usage: orthrus iac [OPTIONS] PATH

  Audit Infrastructure-as-Code for misconfigurations (offline, no network).

  Scans Dockerfiles, docker-compose, and Terraform under PATH (a file or a
  directory) for root containers, unpinned/secret-bearing images, privileged
  or docker-socket-mounted services, world-open security groups, public
  buckets, unencrypted storage, and hardcoded secrets.

Options:
  -o, --output TEXT               Write findings as JSON to this path.
  --fail-on [critical|high|medium|low|info]
                                  Exit non-zero if a finding at/above this
                                  severity is found (for CI).
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus import-traffic`

```text
Usage: orthrus import-traffic [OPTIONS] EXPORT_FILE

  Import a Burp / Caido / HAR proxy history into a program's operator graph
  (PRD §7.12).

  Folds the real attack surface you browsed by hand — hosts and their routes,
  with query/body params and a juicy-score — into the program's assets and
  endpoints, so manual recon flows into the same scan/triage/report pipeline.
  Out-of-scope hosts (third-party CDNs, analytics) are refused by default.

Options:
  --program TEXT                  Operator-graph program to import into.
                                  [required]
  --format [auto|burp|caido|har]  Proxy-export format.  [default: auto]
  --in-scope TEXT                 In-scope domain(s); creates the program if
                                  new, else adds to its scope.
  --authorization TEXT            Authorization source (required to create a
                                  new program).
  --no-scope-filter               Import every host in the file, even out-of-
                                  scope (default: refuse out-of-scope).
  --json                          Emit the import result as JSON.
  --help                          Show this message and exit.
```

## `orthrus mcp`

```text
Usage: orthrus mcp [OPTIONS]

  Run the ORTHRUS MCP server (stdio) — expose scans/findings as agent tools.

  Lets an MCP-capable AI agent query ORTHRUS results (list_scans, get_scan,
  get_findings, list_modules). Needs the [mcp] extra.

Options:
  --help  Show this message and exit.
```

## `orthrus migrate`

```text
Usage: orthrus migrate [OPTIONS]

  Promote existing v0.1 scans/findings into the v2.0 operator graph (PRD
  §4.2).

  Additive and idempotent — creates a 'Legacy v0.1 import' program and upserts
  every scan's assets/findings into the unified graph without touching the
  v0.1 tables, so it's safe to re-run and trivially reversible.

Options:
  --dry-run  Report what would migrate; write nothing.
  --help     Show this message and exit.
```

## `orthrus modules`

```text
Usage: orthrus modules [OPTIONS] [NAME]

  List scanner and exploit-confirmation modules, or detail one by NAME.

  With no NAME, list every module (the names accepted by ``orthrus scan
  --modules``). Pass a NAME to filter to a single scanner (by module name or
  vuln type) or confirmer (by name or a vuln type it handles).

Options:
  --json              Emit the inventory as JSON (stdout).
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus monitor`

```text
Usage: orthrus monitor [OPTIONS] [TARGET]

  Re-scan a TARGET and report drift vs the previous run.

  Continuous monitoring: each run takes a fresh snapshot, stores it, and diffs
  it against the target's previous snapshot. By default it monitors the
  *attack surface* (recon only) — hosts that appeared/vanished, new IPs, newly
  exposed ports. With --deep it runs a full vulnerability scan and also
  reports NEW and RESOLVED findings. Use --watch to run hands-off on an
  interval (each pass auto-diffs against the previous one), --webhook to get
  paged on change, and --fail-on-change for a CI gate.

Options:
  --target-file TEXT    File of targets (one per line; '#' comments ok) to
                        monitor as a portfolio.
  --scope TEXT          Scope token(s); defaults to the target host
                        (+subdomains).
  --baseline TEXT       Scan id to diff against (default: this target's most
                        recent prior scan).
  --webhook TEXT        POST a JSON drift alert to this URL
                        (Slack/Teams/custom).
  --fail-on-change      Exit non-zero when drift is detected (for cron/CI).
  --deep                Run a full vuln scan and also report NEW/RESOLVED
                        findings (not just hosts).
  --watch SECONDS       Run continuously, re-snapshotting every N seconds
                        (Ctrl-C to stop).
  --max-runs INTEGER    With --watch, stop after N iterations (0 = run until
                        stopped).
  --no-host-gather      Skip the host-gather pass (faster, fewer sources).
  --json                Emit the drift report as JSON (stdout).
  --exclude-paths TEXT  Comma-separated regex paths to exclude (scope).
  --scan-id TEXT        Custom scan identifier for this snapshot.
  --rate-limit FLOAT    Max requests/sec per domain.
  --timeout FLOAT       HTTP request timeout (s).
  -v, --verbose TEXT    Log level.
  --help                Show this message and exit.
```

## `orthrus note`

```text
Usage: orthrus note [OPTIONS]

  Save an operator note (methodology, per-program tips, recon summaries).

Options:
  --title TEXT      Note title.  [required]
  --body TEXT       Note body (markdown). Or use --body-file.
  --body-file FILE  Read the note body from a markdown file.
  --program TEXT    Attach the note to a program.
  --tags TEXT       Comma-separated tags.
  --help            Show this message and exit.
```

## `orthrus notes`

```text
Usage: orthrus notes [OPTIONS]

  List or search operator notes.

Options:
  --program TEXT  Filter to one program.
  --tag TEXT      Filter to one tag.
  --search TEXT   Full-text search over title/body/tags.
  --help          Show this message and exit.
```

## `orthrus notify`

```text
Usage: orthrus notify [OPTIONS]

  Push a scan's high-severity findings to Slack and/or Jira.

  Slack sends one summary message; Jira opens one issue per finding.
  Credentials come from flags or ORTHRUS_SLACK_WEBHOOK / ORTHRUS_JIRA_* env
  vars. Use --dry-run to preview the exact payloads without sending anything.

Options:
  --scan-id TEXT                  Scan identifier from a previous run.
                                  [required]
  --min-severity [critical|high|medium|low|info]
                                  Only notify on findings at or above this
                                  severity.
  --slack TEXT                    Slack incoming-webhook URL (or
                                  ORTHRUS_SLACK_WEBHOOK).
  --jira-url TEXT                 Jira base URL.
  --jira-user TEXT                Jira account email.
  --jira-token TEXT               Jira API token.
  --jira-project TEXT             Jira project key.
  --dry-run                       Print the payloads instead of sending them.
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus panic`

```text
Usage: orthrus panic [OPTIONS]

  Emergency kill switch: halt ALL outbound requests + abort in-flight scans
  (PRD §8.3).

  Engaging writes a flag the scope-enforced HTTP client checks before every
  request — deny-by-default becomes deny-everything until you `--clear` it.

Options:
  --clear        Lift a previously-engaged panic state.
  --reason TEXT  Why you're pulling the switch (recorded in the flag).
  --help         Show this message and exit.
```

## `orthrus patch`

```text
Usage: orthrus patch [OPTIONS]

  Generate concrete remediation patches (config/code) for a scan's findings.

  Groups findings by fix and attaches paste-able templated patches per vuln
  type (security headers, parameterized queries, cookie flags, CSP, Terraform
  for cloud posture, …). With --llm, types without a template get a context-
  specific patch from an Anthropic model (opt-in, best-effort). Markdown to
  stdout by default.

Options:
  --scan-id TEXT                  Scan identifier from a previous run.
                                  [required]
  --min-severity [critical|high|medium|low|info]
                                  Only patch findings at or above this
                                  severity.
  --vuln-type TEXT                Only generate patches for this vuln_type.
  --llm                           Ask an Anthropic model for a patch where no
                                  template fits (needs API key).
  --model TEXT                    LLM model id (with --llm).
  -o, --output FILE               Write the patch bundle to this file instead
                                  of stdout.
  --json                          Emit machine-readable JSON instead of
                                  Markdown.
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus plan`

```text
Usage: orthrus plan [OPTIONS]

  Suggest the next steps for a program, grounded in its graph state (PRD
  §7.10).

  A deterministic, no-hallucination planner: it reads the program's assets,
  endpoints, findings, scan history and scope, then prints a priority-ranked
  list of the concrete `orthrus` commands to run next — each with the count
  it's based on. The honest core of the bounded operator agent.

Options:
  --program TEXT  Operator-graph program to plan for.  [required]
  --json          Emit the ranked action list as JSON.
  --help          Show this message and exit.
```

## `orthrus program-findings`

```text
Usage: orthrus program-findings [OPTIONS]

  List a program's operator-graph findings (the triage queue), priority-
  ranked.

  The read side of the operator loop: recon → scan promotes findings here, and
  this surfaces them by name/status so the planner's suggested commands land
  somewhere real. Sorted by priority score (juiciest first).

Options:
  --program TEXT  Operator-graph program to list.  [required]
  --status TEXT   Filter by finding status (e.g. new, confirmed, filed).
  --json          Emit findings as JSON.
  --help          Show this message and exit.
```

## `orthrus program-policy`

```text
Usage: orthrus program-policy [OPTIONS]

  Set a program's traffic policy: a rate ceiling and an identifying header.

  Most programs state a max request rate and ask you to identify your traffic.
  Saved here, both are applied automatically on every `orthrus bounty
  --program NAME` run — the rate is a hard cap (never exceeded), the header is
  attached to every request.

Options:
  --program TEXT   Saved program to set policy on.  [required]
  --max-rps FLOAT  Rate ceiling (req/s) — honored as a cap on every run.
  --identify TEXT  Identifying header to send, e.g. "X-Bug-Bounty: yourname".
  --clear          Clear both policy fields.
  --help           Show this message and exit.
```

## `orthrus program-scan`

```text
Usage: orthrus program-scan [OPTIONS]

  Scan a program's live in-scope assets → promote findings into the operator
  graph (PRD Phase 2).

  Bridges recon → scan → triage queue: takes the live assets the recon engine
  discovered, runs the full scan+confirm pipeline over them, and folds the
  bugs into the program's ProgramFinding queue (deduped, priority-scored,
  ScanRun- linked) — where the cockpit Findings tab and triage see them.

Options:
  --program TEXT                  Operator-graph program to scan.  [required]
  --min-confidence [confirmed|firm|tentative]
                                  Confidence floor for promoted findings.
  --max-assets INTEGER            Cap live assets scanned this run.
  --aggressive                    Aggressive scanning.
  --help                          Show this message and exit.
```

## `orthrus programs`

```text
Usage: orthrus programs [OPTIONS]

  List saved bug-bounty programs (scope, authorization, last run).

Options:
  --help  Show this message and exit.
```

## `orthrus proxy`

```text
Usage: orthrus proxy [OPTIONS]

  Run a scope-aware capturing proxy to feed the scanner from a manual browse.

  Point your browser / HTTP client at http://HOST:PORT and browse the
  authorized target; every in-scope request's endpoint + parameters are
  captured (into a scan with --scan-id). Deny-by-default: out-of-scope
  requests are blocked unless --allow-out-of-scope is set (pass-through
  traffic is never captured). HTTPS is tunneled opaquely (no TLS
  interception).

Options:
  --port INTEGER        Local port to listen on.
  --host TEXT           Local bind address.
  --scope TEXT          Authorized scope: comma-separated domains / CIDRs
                        (required — deny by default).
  --scan-id TEXT        Persist captured endpoints into this existing scan.
  --allow-out-of-scope  Pass through (don't block) out-of-scope requests; they
                        are never captured.
  --exclude-paths TEXT  Comma-separated regex paths to never forward.
  -v, --verbose TEXT    Log level.
  --help                Show this message and exit.
```

## `orthrus recon`

```text
Usage: orthrus recon [OPTIONS]

  Run reconnaissance only.

Options:
  -t, --target TEXT               Target URL.  [required]
  --scope TEXT                    Scope: wildcard domains / CIDR ranges.
  --fingerprint / --no-fingerprint
                                  Run technology fingerprinting.
  --crawl / --no-crawl            Run the web crawler.
  --js / --no-js                  Run JS endpoint/secret analysis.
  --content / --no-content        Run content discovery.
  --waf / --no-waf                Run WAF detection.
  --api / --no-api                Run API discovery.
  --dns / --no-dns                Run DNS enumeration (domain targets).
  --ip-intel / --no-ip-intel      Resolve the target's IP intelligence
                                  (PTR/ASN/geo/cloud).
  --mine-params / --no-mine-params
                                  Mine endpoints for hidden parameters.
  --subdomains                    Run subdomain enumeration (needs *.domain
                                  scope).
  --host-gather                   Gather the host footprint (CT logs, reverse-
                                  IP, /24 reverse-DNS, Wayback).
  --wayback                       Query the Wayback Machine for historical
                                  URLs.
  --ports                         Run Nmap port scan (needs the nmap binary).
  --crawl-depth INTEGER           Maximum crawl depth.
  --max-pages INTEGER             Maximum pages to crawl.
  --rate-limit FLOAT              Max requests/sec per domain.
  --timeout FLOAT                 HTTP request timeout (s).
  --proxy TEXT                    HTTP/SOCKS5 proxy URL.
  --auth-cookie TEXT              Pre-authenticated session cookie string.
  --login-url TEXT                URL to POST credentials to before recon.
  --login-data TEXT               Login body: 'user=admin&password=admin' or a
                                  JSON object.
  --login-token-field TEXT        Dotted path into a JSON login response to
                                  use as the bearer token.
  --login-check TEXT              Substring proving the session is
                                  authenticated.
  --import TEXT                   Import an
                                  OpenAPI/Swagger/GraphQL/HAR/Postman spec
                                  (file path or in-scope URL).
  --exclude-paths TEXT            Comma-separated regex paths to exclude.
  --scan-id TEXT                  Custom scan identifier.
  -o, --output TEXT               Optional JSON report output path.
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus recon-run`

```text
Usage: orthrus recon-run [OPTIONS]

  Run continuous recon for a program: enumerate its scope into the operator
  graph.

  Every available source (crt.sh/certspotter/DNS/wayback + subfinder/amass if
  installed) discovers assets, which are deduped into the graph with
  first/last-seen so this reports what's NEW since the last run. Populates the
  cockpit's Assets tab.

Options:
  --program TEXT            Operator-graph program to recon.  [required]
  --in-scope TEXT           In-scope domain(s); creates the program if new,
                            else adds to its scope.
  --authorization TEXT      Authorization source (required to create a new
                            program).
  --sources TEXT            Comma-separated recon adapters, or 'all'.
  --notify-slack WEBHOOK    POST a summary to this Slack webhook when NEW
                            assets are found.
  --notify-discord WEBHOOK  POST a summary to this Discord webhook when NEW
                            assets are found.
  --json                    Emit the recon result as JSON.
  --help                    Show this message and exit.
```

## `orthrus recon-watch`

```text
Usage: orthrus recon-watch [OPTIONS]

  Continuously re-run recon for a program, alerting on NEW assets (PRD §7.2).

  Runs when nobody's watching: each pass folds fresh discoveries into the
  graph and fires Slack/Discord alerts on new in-scope assets. Interrupt to
  stop.

Options:
  --program TEXT            Saved operator-graph program.  [required]
  --interval INTEGER        Seconds between recon passes.  [default: 3600]
  --max-runs INTEGER        Stop after N passes (0 = run until interrupted).
  --sources TEXT            Comma-separated recon adapters, or 'all'.
  --notify-slack WEBHOOK    Alert this Slack webhook on new assets.
  --notify-discord WEBHOOK  Alert this Discord webhook on new assets.
  --help                    Show this message and exit.
```

## `orthrus replay`

```text
Usage: orthrus replay [OPTIONS]

  Resend a recorded request with optional tweaks — the mini-Repeater.

  Source the request from a finding (`--scan-id --finding-id`), a raw request
  file (`--request-file`), or an ad-hoc `--url`; tweak it with `--method`,
  `--header`, `--body`, `--url`; and observe the response. Scope-enforced.

Options:
  --request-file FILE  Raw HTTP request file (Burp-style paste).
  --scan-id TEXT       Replay a finding's recorded request from this scan.
  --finding-id TEXT    Finding id (with --scan-id) whose recorded request to
                       replay.
  --url TEXT           Ad-hoc URL to request, or override the source URL.
  --method TEXT        Override the HTTP method.
  --header TEXT        Add/override a header 'Name: value' (repeatable).
  --body TEXT          Override the request body.
  --scope TEXT         Scope token(s); defaults to the request host.
  --scheme TEXT        Scheme for origin-form raw requests (default https).
  --repeat INTEGER     Send the request N times (timing/consistency).
  --follow-redirects   Follow redirects.
  --show-body          Print the full response body (default: a preview).
  -v, --verbose TEXT   Log level.
  --help               Show this message and exit.
```

## `orthrus report`

```text
Usage: orthrus report [OPTIONS]

  Generate a report from an existing scan.

Options:
  --scan-id TEXT                  Scan identifier to report on.  [required]
  --format [json|html|pdf|csv|sarif|md|navigator]
                                  Report format ('navigator' = MITRE ATT&CK
                                  Navigator layer JSON).
  --template TEXT                 Template: executive/technical/compliance.
  --logo TEXT                     Logo image embedded in HTML/PDF reports.
  --min-severity TEXT             Only report findings >= this severity.
  -o, --output TEXT               Output file path.
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus runbook`

```text
Usage: orthrus runbook [OPTIONS]

  Consolidated remediation runbook — the few fixes that retire a scan's risk.

  Collapses findings that share a fix into one prioritised action, ordered so
  the highest-leverage change (one that breaks a correlated attack path) is
  first. Emits Markdown to stdout by default; use -o to write a file or --json
  for data.

Options:
  --scan-id TEXT                  Scan identifier from a previous run.
                                  [required]
  --min-severity [critical|high|medium|low|info]
                                  Only include findings at or above this
                                  severity.
  -o, --output FILE               Write the runbook to this file instead of
                                  stdout.
  --json                          Emit machine-readable JSON instead of
                                  Markdown.
  -v, --verbose TEXT              Log level.
  --help                          Show this message and exit.
```

## `orthrus scan`

```text
Usage: orthrus scan [OPTIONS]

  Run the full pipeline: recon -> scan -> exploit -> report.

Options:
  --config FILE                   Load scan options from a TOML file ([scan]
                                  table); CLI flags override it.
  -t, --target TEXT               Target URL (required unless --resume).
  --target-file FILE              File of targets (one per line; '#' comments
                                  allowed) for sequential batch scanning.
  --scope TEXT                    Scope: wildcard domains / CIDR ranges.
  --modules TEXT                  Comma-separated scanner modules.
  --tools TEXT                    External tool adapters to run (e.g. 'nuclei'
                                  or 'all'); needs the binary on PATH.
  --aggressive                    Enable aggressive scanning.
  --rate-limit FLOAT              Max requests/sec per domain.
  --crawl-depth INTEGER           Maximum crawl depth.
  --max-pages INTEGER             Maximum pages to crawl.
  --timeout FLOAT                 HTTP request timeout (s).
  --proxy TEXT                    HTTP/SOCKS5 proxy URL.
  --auth-cookie TEXT              Pre-authenticated session cookie string.
  --auth-script TEXT              Playwright login script path (deferred).
  --identities FILE               JSON file of identities for authorization
                                  testing (BOLA/BFLA). List of
                                  {"name","cookie"?,"token"?,"headers"?};
                                  first = privileged baseline.
  --login-url TEXT                URL to POST credentials to before scanning.
  --login-data TEXT               Login body: 'user=admin&password=admin' or a
                                  JSON object.
  --login-token-field TEXT        Dotted path into a JSON login response to
                                  use as the bearer token.
  --login-check TEXT              Substring proving the session is
                                  authenticated.
  --csrf-field TEXT               Anti-CSRF form field to harvest from the
                                  login page and replay in the login body.
  --csrf-header TEXT              Request header to mirror the harvested CSRF
                                  token into.
  --csrf-url TEXT                 Page to GET for the CSRF token (default:
                                  --login-url).
  --totp-secret TEXT              Base32 MFA secret; a TOTP code is submitted
                                  with login.
  --totp-field TEXT               Login body field for the TOTP code (default:
                                  otp).
  --oauth2-token-url TEXT         OAuth2 token endpoint to acquire a bearer
                                  token from.
  --oauth2-grant [password|client_credentials|refresh_token]
                                  OAuth2 grant type (default: password).
  --oauth2-client-id TEXT         OAuth2 client id.
  --oauth2-client-secret TEXT     OAuth2 client secret.
  --oauth2-username TEXT          OAuth2 password-grant username.
  --oauth2-password TEXT          OAuth2 password-grant password.
  --oauth2-scope TEXT             OAuth2 requested scope.
  --oauth2-refresh-token TEXT     OAuth2 refresh token (refresh_token grant).
  --oauth2-token-field TEXT       Dotted path to the token in the OAuth2 JSON
                                  response (default: access_token).
  --reauth                        Silently re-run the login flow and retry
                                  when a response looks unauthenticated mid-
                                  scan.
  --reauth-marker TEXT            Body substring that signals a dropped
                                  session (repeatable; overrides defaults).
  --import TEXT                   Import an
                                  OpenAPI/Swagger/GraphQL/HAR/Postman spec
                                  (file path or in-scope URL).
  --templates TEXT                Run declarative templates: 'builtin' for the
                                  bundled set, or a file/directory path.
  --user-agent TEXT               User-Agent string or 'random'.
  --callback TEXT                 Advertise host for the local OOB listener.
  --interactsh                    Use a real Interactsh OOB collaborator
                                  (public pool) for blind/OOB detection.
  --interactsh-server TEXT        Specific Interactsh server host (default:
                                  public pool); implies --interactsh.
  --interactsh-token TEXT         Auth token for a self-hosted Interactsh
                                  server.
  --no-exploit                    Skip exploitation confirmation phase.
  --browser / --no-browser        Use headless browser (DOM/stored XSS).
  --waf-adapt / --no-waf-adapt    On a WAF block/challenge, rotate request
                                  identity and retry once (and report scan-
                                  reliability).
  --exclude-paths TEXT            Comma-separated regex paths to exclude.
  --headers TEXT                  Extra headers as JSON object.
  --threads INTEGER               Concurrent scanner threads.
  --distributed                   Distribute targets across Celery workers.
  --workers INTEGER               Worker count (distributed partitioning).
  --redis TEXT                    Redis broker URL (distributed mode).
  --scan-id TEXT                  Custom scan identifier.
  --resume                        Resume an interrupted scan by --scan-id,
                                  reusing its stored config/scope and skipping
                                  phases already completed. Report options are
                                  taken from the CLI.
  -o, --output TEXT               Report output path.
  --format [json|html|pdf|csv|sarif|md|navigator]
                                  Report format ('navigator' = MITRE ATT&CK
                                  Navigator layer JSON).
  --template TEXT                 Report template:
                                  executive/technical/compliance.
  --min-severity TEXT             Only report findings >= this severity.
  --logo TEXT                     Logo image embedded in HTML/PDF reports.
  --har TEXT                      Record a browser HAR to this path
                                  (evidence).
  --fail-on [critical|high|medium|low|info]
                                  Exit 3 if any finding at or above this
                                  severity is found (CI gating). Applies to
                                  single-target scans.
  -q, --quiet                     Suppress phase chrome and per-module
                                  chatter; show only the banner, scope and
                                  final results (pairs with --fail-on for CI).
  --dry-run                       Resolve the scope and scanner plan, print
                                  them, and exit without sending any requests
                                  (confirm the engagement boundary before
                                  scanning).
  -v, --verbose TEXT              Log level: debug/info/warning/error.
  --help                          Show this message and exit.
```

## `orthrus scans`

```text
Usage: orthrus scans [OPTIONS]

  List previous scans (id, status, phase, findings) for resume/report.

Options:
  --status TEXT       Filter by status: running / completed / failed.
  --limit INTEGER     Maximum number of scans to list.
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus serve`

```text
Usage: orthrus serve [OPTIONS]

  Run the ORTHRUS REST API (scans/findings + operator-graph CRUD over HTTP).

  Needs the [api] extra (fastapi + uvicorn). Endpoints: /health, /api/scans*,
  /api/programs* (operator graph). With --cockpit, the built React/Tauri
  cockpit is served at /cockpit (build it first: `npm --prefix cockpit run
  build`).

Options:
  --host TEXT     Bind address for the API server.
  --port INTEGER  Port for the API server.
  --cockpit       Also serve the v2.0 operator cockpit at /cockpit.
  --help          Show this message and exit.
```

## `orthrus submission`

```text
Usage: orthrus submission [OPTIONS]

  Record or update a bug-bounty submission (status, payout, link).

Options:
  --id TEXT                       Existing submission id to UPDATE (else a new
                                  one is added).
  --program TEXT                  Program name (required when adding).
  --title TEXT                    Bug title (required when adding).
  --platform TEXT                 hackerone/bugcrowd/intigriti/yeswehack/immun
                                  efi/generic.
  --severity TEXT
  --status [draft|filed|triaged|accepted|duplicate|informative|resolved|rewarded|closed|n-a]
                                  Submission lifecycle state.
  --bounty FLOAT                  Payout amount.
  --currency TEXT
  --url TEXT                      Link to the report on the platform.
  --notes TEXT
  --help                          Show this message and exit.
```

## `orthrus submissions`

```text
Usage: orthrus submissions [OPTIONS]

  List tracked submissions and roll up earnings.

Options:
  --program TEXT  Filter to one program.
  --help          Show this message and exit.
```

## `orthrus suppress`

```text
Usage: orthrus suppress [OPTIONS]

  Add a mute rule so known-noise findings stay out of a program's report
  queue.

  At least one of --vuln-type / --host / --title-contains is required (an
  empty rule would mute everything, so it's refused). Muted findings are still
  counted in the campaign summary — nothing silently disappears.

Options:
  --program TEXT         Program the rule applies to.  [required]
  --vuln-type TEXT       Mute this vuln_type (e.g. security-headers).
  --host TEXT            Mute this host (matches the host and its subdomains).
  --title-contains TEXT  Mute findings whose title contains this text.
  --reason TEXT          Why it's muted (kept for the audit trail).
  --help                 Show this message and exit.
```

## `orthrus suppressions`

```text
Usage: orthrus suppressions [OPTIONS]

  List (or --remove) a program's mute rules.

Options:
  --program TEXT    Program to list/edit rules for.  [required]
  --remove INTEGER  Remove the rule at this index (from the list).
  --help            Show this message and exit.
```

## `orthrus surface`

```text
Usage: orthrus surface [OPTIONS]

  Render a scan's recon (hosts / ports / technologies / endpoints) as an
  interactive attack-surface graph — a self-contained HTML page.

Options:
  --scan-id TEXT      Scan whose recon to visualize.  [required]
  -o, --output TEXT   Output HTML file.
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus team`

```text
Usage: orthrus team [OPTIONS] COMMAND [ARGS]...

  Manage team members + per-program roles on the operator graph (PRD §9).

  Team mode is opt-in: with no members a program behaves single-user as
  before. Add users, mint their API keys, and grant per-program roles
  (owner/member/viewer); the REST API then enforces those roles once a program
  has members.

Options:
  --help  Show this message and exit.

Commands:
  add-user  Create a team USER (by email).
  grant     Grant (or change) a USER's ROLE on a PROGRAM.
  key       Mint a fresh API key for EMAIL (invalidates the previous one).
  members   List a PROGRAM's members and their roles.
  revoke    Revoke a USER's access to a PROGRAM.
  users     List team members.
```

## `orthrus triage`

```text
Usage: orthrus triage [OPTIONS]

  Deduplicate + cluster a scan's findings into distinct issues.

  A real scan reports the same bug at many URLs (IDOR on /order/1..999, a
  missing header on every route). This folds id-like URLs together
  (/order/{id}) and clusters by type + location, so a 600-finding list becomes
  the handful of issues that actually need fixing — each with its severity, a
  count, and the affected URLs. With --llm, an LLM judge additionally flags
  clusters that look like false positives (opt-in; no-ops without an API key).

Options:
  --scan-id TEXT      Scan identifier from a previous run.  [required]
  --llm               Use an LLM judge to flag likely false positives (needs
                      ORTHRUS_ANTHROPIC_API_KEY).
  --model TEXT        LLM model id for --llm (default: a fast Claude Haiku).
  --json              Emit the triaged report as JSON (stdout).
  -v, --verbose TEXT  Log level.
  --help              Show this message and exit.
```

## `orthrus update`

```text
Usage: orthrus update [OPTIONS]

  Refresh threat-intel feeds (CISA KEV + EPSS) used to enrich CVE findings.

  Fetches the CISA Known Exploited Vulnerabilities catalog from cisa.gov and
  the full EPSS dataset from FIRST.org (both trusted data sources, not the
  target) and rewrites the bundled seeds so CVE findings are flagged when
  actively exploited (KEV) and prioritised by exploit probability (EPSS). Each
  feed refreshes independently — one failing does not abort the other.

Options:
  --help  Show this message and exit.
```

