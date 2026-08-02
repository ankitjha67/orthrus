# Methodology & accuracy

This document exists because a fair critique of any automated - and especially any
AI-assisted - security scanner is: *"how do I know it isn't just confidently wrong?"*
A tool that finds known bugs but also cries wolf on clean code is worse than useless. So
this page states, precisely, **what ORTHRUS measures, how, where AI is and isn't in the
loop, and the actual numbers** - with reproduction commands and honest limitations.

## The two questions, separated

- **Recall** - *does it find real bugs?* Proven by the end-to-end benchmark
  (`orthrus.benchmark.runner` + `docs/PROOF.md`): scan a target with enumerated ground
  truth, measure the fraction detected.
- **Precision** - *does it stay quiet on safe code?* This is the harder and more important
  question, and the one a detection-only benchmark never answers. Recall without precision
  is exactly the "confidently wrong" failure mode. This is what the detector corpus adds.

## Detector-level precision/recall corpus (reproducible, CI-gated)

Every passive scanner has a **pure verdict function** - it takes plain input (response
headers, a TLS-facts dict, an HTML string, a `Set-Cookie` line, a DNS record set) and
returns findings, with no network or browser. That makes its accuracy measurable
deterministically. `orthrus/benchmark/data/detector_corpus.json` is a labelled corpus of
**vulnerable** and **known-clean** inputs; `orthrus.benchmark.detectors.run_detector_corpus`
runs each case through the real detector and tallies a confusion matrix.

The clean cases are deliberately **hard negatives** - the edges where a sloppy detector
over-fires: a third-party script that *does* carry an `integrity=` hash, a `csrf` parameter
that superficially looks like a session id, a protocol-relative resource, softfail-SPF with
a quarantine DMARC policy, a clean HTTP response where HSTS is not required.

Current corpus (run `pytest tests/unit/test_benchmark_metrics.py` or the snippet below):

| Detector | TP | FP | TN | FN | Precision | Recall | Specificity |
|---|---:|---:|---:|---:|---:|---:|---:|
| headers | 4 | 0 | 3 | 0 | 1.00 | 1.00 | 1.00 |
| tls | 4 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 |
| sri | 2 | 0 | 4 | 0 | 1.00 | 1.00 | 1.00 |
| session-url | 2 | 0 | 4 | 0 | 1.00 | 1.00 | 1.00 |
| cookie | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 |
| email-auth | 3 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 |
| mixed-content | 2 | 0 | 3 | 0 | 1.00 | 1.00 | 1.00 |
| **Aggregate** | **19** | **0** | **20** | **0** | **1.00** | **1.00** | **1.00** |

**Read this honestly:** this is **0 false positives and 0 misses on a 39-case corpus of
hard positives and hard negatives** - not a claim of universal 100% precision. Its value is
twofold: it proves the false-positive *guards* hold on the tricky cases, and it is wired as
a **CI regression gate** (`test_detector_corpus_has_no_false_positives_or_misses`) - the day
a change makes a detector fire on clean input, a `TN` flips to `FP`, precision drops, and CI
goes red. The corpus is meant to **grow**; adding a case that legitimately fails documents a
real limitation rather than hiding it.

## Confirmation efficacy - the thesis, as a number

ORTHRUS's actual differentiator is not breadth; it is that a finding is `tentative` until a
**confirmation** module re-proves it with a fresh nonce / OOB callback / browser-executed
PoC, and only then becomes `confirmed`. `orthrus.benchmark.metrics.ConfirmationEfficacy`
measures exactly this: given the detection-only confusion matrix (`pre`) and the
post-confirmation matrix (`post`), it reports **false positives removed**, **true positives
kept**, and **precision gain**. Good confirmation strips false alarms while keeping real
findings - that is the value proposition reduced to three numbers. (The live end-to-end
efficacy run needs the scan+confirm harness against a target with ground truth; the metric
and its guards are unit-tested here, and the harness is documented for reproduction.)

## Where AI is - and is not - in the loop

This matters most for the "AI might be misleading" concern:

- **AI is not the detector.** Every finding is produced by a **deterministic** scanner or
  confirmer. The LLM cannot introduce a vulnerability that a detector did not already emit.
- **The AI report writer** (`orthrus ai-report`) *narrates* the fixed findings and their
  verbatim evidence. It is explicitly grounded and cannot invent a vulnerability; it turns a
  finished, evidence-backed finding list into prose.
- **The bounded agent planner** selects and sequences scanner/confirmer actions; the
  detection and proof still come from the deterministic modules it drives, and it runs under
  scope enforcement and an audit log.
- **Prioritisation** (`orthrus.risk.priority`, the P1-P4 bands) is pure and deterministic -
  same evidence, same band, with a printed rationale.

So the trust boundary is: **deterministic code finds and proves; AI explains and plans.**

## Limitations (stated, not hidden)

- The corpus measures **pure-verdict passive detectors at the unit level**. Active scanners
  (SQLi/XSS/SSRF request-differentials) and the confirmation phase are measured **end-to-end**
  by `orthrus.benchmark.runner`, which needs a running target with ground truth.
- A self-authored corpus is a **starting point**. Numbers on third-party labelled corpora
  (OWASP Juice Shop, WebGoat, and their non-vulnerable counterparts) are stronger and are the
  next step; this framework is what makes adding them mechanical.
- No claim is made about zero false positives in the wild. The claim is narrow and checkable:
  **0 FP / 0 FN on this corpus, enforced in CI, growing over time.**

## Reproduce

```bash
pytest tests/unit/test_benchmark_metrics.py -q          # metric math + the corpus gate
python -c "from orthrus.benchmark.detectors import run_detector_corpus as r; per,agg,err=r(); print(agg.as_dict())"
```
