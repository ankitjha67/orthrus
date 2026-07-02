#!/usr/bin/env bash
# ORTHRUS quick demo — safe: runs only against the bundled, 127.0.0.1-only,
# intentionally-vulnerable practice target. Nothing external is contacted.
#
# Record it as a GIF/cast with either:
#   asciinema rec orthrus-demo.cast -c ./demo.sh          # then upload / render to GIF
#   termtosvg orthrus-demo.svg      -c ./demo.sh          # animated SVG
#
# Override the CLI if not on PATH:  ORTHRUS="python -m orthrus.main" ./demo.sh
set -eu   # no pipefail: `… | head` intentionally closes the pipe early
PORT="${PORT:-8791}"
ORTHRUS="${ORTHRUS:-orthrus}"
SID="demo-$$"

echo "▶ starting the bundled practice target on 127.0.0.1:${PORT} (local-only, intentionally vulnerable)"
python tests/integration/reflecting_target.py "$PORT" >/dev/null 2>&1 &
TPID=$!
trap 'kill "$TPID" 2>/dev/null || true' EXIT
sleep 2

echo; echo "▶ 1/6  full pipeline: recon → scan → exploitation-confirmation → report"
$ORTHRUS --no-banner scan -t "http://127.0.0.1:${PORT}" --scope 127.0.0.1 --aggressive --no-browser \
  --scan-id "$SID" --modules headers,cors,sqli,xss,jwt,ssrf,cmd-injection,ssti,csrf,idor \
  -o orthrus_report_demo.html --format html

echo; echo "▶ 2/6  collapse findings into reachable attack paths (kill-chains)"
$ORTHRUS --no-banner graph --scan-id "$SID"

echo; echo "▶ 3/6  consolidated remediation runbook (ordered by leverage)"
$ORTHRUS --no-banner runbook --scan-id "$SID" | head -24

echo; echo "▶ 4/6  concrete remediation patches (config/code)"
$ORTHRUS --no-banner patch --scan-id "$SID" | head -22

echo; echo "▶ 5/6  read-only cloud posture (CSPM/IAM) + toxic combinations"
$ORTHRUS --no-banner cloud examples/cloud_inventory.json

echo; echo "▶ 6/6  autonomous agent — plan only (dry-run; allow-listed, scope-enforced, no shell)"
$ORTHRUS --no-banner agent -t "http://127.0.0.1:${PORT}" --scope 127.0.0.1 --no-llm --dry-run --aggressiveness passive

echo; echo "✔ done — full HTML report written to orthrus_report_demo.html"
