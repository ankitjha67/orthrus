"""Big-Four-grade AI penetration-test report writer.

The report is a **hybrid**: every fact — findings, CVSS, CWE/OWASP/ATT&CK
mappings, and the *verbatim recorded evidence* (request/response, exploitation
proof) — is rendered deterministically from the scan, while a language model
writes the consultant narrative *around* those facts (executive summary,
per-finding technical description / business impact / likelihood / exploitation
walkthrough / remediation, attack-chain stories, and a phased remediation
roadmap).

Because the findings are fixed and the evidence is quoted verbatim, the model
**cannot invent a vulnerability** — it can only explain and contextualise what
the tool already proved. Narrative generation is best-effort: if the model is
unavailable, each section falls back to the deterministic content so the report
always completes. ``--dry-run`` produces the full scaffold with the evidence and
no model calls.

The model client is injected (see ``orthrus.ai.providers``), so this module is
provider-agnostic and unit-tested against a fake client with no network.
"""

from __future__ import annotations

from collections.abc import Callable

from orthrus.ai.providers import LLMClient, LLMError
from orthrus.utils.logger import get_logger

logger = get_logger("ai.report_writer")

_EVIDENCE_CAP = 6000      # verbatim evidence kept in the report (per block)
_LLM_EVIDENCE_CAP = 2500  # evidence slice sent to the model (redacted upstream)
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SYSTEM_PROMPT = (
    "You are a Principal Security Consultant at a Big Four professional-services firm, "
    "authoring a formal penetration-test report for an enterprise client. Write in precise, "
    "formal, third-person consultant prose — thorough, specific, and evidence-anchored.\n"
    "Rules:\n"
    "- Ground every statement ONLY in the facts provided; never invent findings, values, CVEs, "
    "or evidence not present in the input.\n"
    "- Be comprehensive and detailed — prefer complete, multi-paragraph explanations over "
    "terse notes; this is a premium deliverable.\n"
    "- Reference the concrete evidence given (parameters, URLs, payloads, response indicators).\n"
    "- Use formal English; no marketing language, no hedging filler, no meta-commentary.\n"
    "- Output GitHub-flavoured Markdown for the requested section ONLY — no preamble, no "
    "'As an AI', no restating the prompt."
)


def _trunc(text: str | None, cap: int) -> str:
    text = text or ""
    return text if len(text) <= cap else text[:cap] + f"\n… [truncated, {len(text) - cap} more chars]"


def _sev_label(s: str) -> str:
    return (s or "info").upper()


# --------------------------------------------------------------------------
# Deterministic scaffold (facts + verbatim evidence)
# --------------------------------------------------------------------------

def _cover(ctx: dict) -> str:
    scan, summ = ctx["scan"], ctx["summary"]
    c = summ["counts"]
    order = ["critical", "high", "medium", "low", "info"]
    dist = " · ".join(f"{c.get(s, 0)} {s}" for s in order)
    scope = scan.get("scope") or {}
    scope_str = ", ".join(
        (scope.get("domains") or []) + (scope.get("ip_ranges") or [])
    ) or "as authorised for the engagement"
    return (
        f"# Penetration Test Report — {scan.get('target') or 'Target Application'}\n\n"
        "**Classification:** CONFIDENTIAL — for the intended recipient only\n"
        "**Assessment type:** Automated Dynamic Application Security Testing (DAST) with "
        "exploitation confirmation\n"
        f"**Target:** {scan.get('target') or '—'}  \n"
        f"**Authorised scope:** {scope_str}  \n"
        f"**Scan reference:** {scan.get('id')}  \n"
        f"**Report date:** {ctx.get('generated_at')}  \n"
        "**Prepared by:** ORTHRUS Automated Security Assessment Platform  \n"
        "**Report version:** 1.0\n\n"
        "| Metric | Value |\n|---|---|\n"
        f"| Total findings | {summ['total']} |\n"
        f"| Confirmed by active exploitation | {summ['confirmed']} |\n"
        f"| Severity distribution | {dist} |\n\n"
        "> **Basis of report.** Findings are produced by automated scanning and, where marked "
        "*confirmed*, re-proven by non-destructive exploitation. The narrative in this document "
        "is AI-generated and grounded strictly in the recorded evidence — it explains and "
        "contextualises findings but does not create them. This deliverable should be reviewed by "
        "a qualified assessor before release to the client.\n"
    )


def _methodology(ctx: dict) -> str:
    scan = ctx["scan"]
    return (
        "## 2. Assessment Scope, Approach & Methodology\n\n"
        "### 2.1 Scope & Timeline\n"
        f"- **Target under test:** {scan.get('target') or '—'}\n"
        f"- **Assessment window:** {scan.get('started_at') or '—'} to "
        f"{scan.get('completed_at') or '—'}\n"
        "- **Rules of engagement:** deny-by-default scope enforcement; every request was validated "
        "against the authorised scope before transmission, and exploitation was non-destructive.\n\n"
        "### 2.2 Methodology\n"
        "The assessment followed a four-phase methodology:\n\n"
        "1. **Reconnaissance** — crawling, technology fingerprinting, content and parameter "
        "discovery, and passive intelligence to enumerate the attack surface.\n"
        "2. **Vulnerability scanning** — active and passive testing across injection, cross-site "
        "scripting, access control, authentication/session, server-side, configuration/transport, "
        "and API classes.\n"
        "3. **Exploitation confirmation** — the interesting findings were actively re-proven "
        "(canary values, out-of-band callbacks, controlled reads) to distinguish *tentative* from "
        "*demonstrably exploitable* conditions.\n"
        "4. **Reporting** — findings are CVSS-scored (v3.1 and v4.0), mapped to OWASP, CWE, "
        "PCI-DSS, NIST CSF, and MITRE ATT&CK / D3FEND, correlated into attack chains, and "
        "documented with evidence.\n\n"
        "### 2.3 Risk-Rating Methodology\n"
        "Each finding carries a CVSS base score and a qualitative severity band "
        "(Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, Informational 0.0). "
        "Severity reflects technical impact and exploitability; the business-impact narrative in "
        "each finding contextualises that rating for the client's environment.\n\n"
        "### 2.4 Limitations\n"
        "This was an automated assessment. Automated testing may not exercise complex "
        "multi-step business logic and can yield false negatives; the absence of a finding is not "
        "a guarantee of security. Manual verification by a qualified assessor is recommended, "
        "particularly for authorisation and business-logic controls.\n"
    )


def _overview(ctx: dict) -> str:
    summ = ctx["summary"]
    findings = ctx["findings"]
    order = ["critical", "high", "medium", "low", "info"]
    rows = "\n".join(f"| {s.capitalize()} | {summ['counts'].get(s, 0)} |" for s in order)
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["vuln_type"]] = by_type.get(f["vuln_type"], 0) + 1
    cat_rows = "\n".join(
        f"| `{vt}` | {n} |" for vt, n in sorted(by_type.items(), key=lambda x: -x[1])
    ) or "| — | 0 |"
    owasp_rows = "\n".join(
        f"| {cat} | {n} |" for cat, n in sorted((summ.get("owasp_counts") or {}).items())
    ) or "| — | 0 |"
    return (
        "## 3. Findings Overview\n\n"
        "### 3.1 Severity Distribution\n\n"
        f"| Severity | Count |\n|---|---|\n{rows}\n\n"
        "### 3.2 Findings by Category\n\n"
        f"| Vulnerability type | Count |\n|---|---|\n{cat_rows}\n\n"
        "### 3.3 OWASP Top 10 (2021) Coverage\n\n"
        f"| OWASP category | Findings |\n|---|---|\n{owasp_rows}\n"
    )


def _finding_metadata(f: dict, index: int) -> str:
    attack = ", ".join(f"{t['id']} {t['name']}" for t in (f.get("attack") or [])) or "—"
    d3fend = ", ".join(f"{d['id']} {d['name']}" for d in (f.get("d3fend") or [])) or "—"
    v3 = f"{f.get('cvss_score')} ({f.get('cvss_vector')})" if f.get("cvss_score") is not None else "—"
    v4 = f"{f.get('cvss_v4_score')} ({f.get('cvss_v4_vector')})" if f.get("cvss_v4_score") is not None else "—"
    return (
        f"### 4.{index} [{_sev_label(f['severity'])}] {f['title']}\n\n"
        "| Attribute | Value |\n|---|---|\n"
        f"| Finding ID | {f.get('id')} |\n"
        f"| Vulnerability type | `{f.get('vuln_type')}` |\n"
        f"| Severity | **{_sev_label(f['severity'])}** |\n"
        f"| Confidence | {f.get('confidence')} |\n"
        f"| CVSS v3.1 | {v3} |\n"
        f"| CVSS v4.0 | {v4} |\n"
        f"| EPSS (exploit probability) | {f.get('epss') if f.get('epss') is not None else '—'} |\n"
        f"| CWE | {f.get('cwe') or '—'} |\n"
        f"| OWASP 2021 | {f.get('owasp') or '—'} |\n"
        f"| MITRE ATT&CK | {attack} |\n"
        f"| MITRE D3FEND | {d3fend} |\n"
        f"| Affected URL | {f.get('url') or '—'} |\n"
        f"| Parameter | {f.get('parameter') or '—'} |\n"
        f"| Detected by | `{f.get('scanner')}` |\n"
    )


def _evidence_block(f: dict) -> str:
    ev = f.get("evidence") or {}
    parts = ["#### Evidence (recorded verbatim)\n"]
    if ev.get("matched_at"):
        parts.append(f"**Match location / indicator:** `{_trunc(str(ev['matched_at']), 500)}`\n")
    if ev.get("request_raw"):
        parts.append("**Request**\n\n```http\n" + _trunc(ev["request_raw"], _EVIDENCE_CAP) + "\n```\n")
    if ev.get("response_raw"):
        parts.append("**Response**\n\n```http\n" + _trunc(ev["response_raw"], _EVIDENCE_CAP) + "\n```\n")
    if ev.get("notes"):
        parts.append(f"**Assessor notes:** {_trunc(str(ev['notes']), 1000)}\n")
    for i, ex in enumerate(f.get("exploitations") or [], 1):
        status = "SUCCEEDED" if ex.get("success") else "attempted"
        parts.append(
            f"**Exploitation confirmation #{i} — {status}**\n\n"
            f"- Technique: `{ex.get('technique')}`\n"
            + (f"- Extracted data: `{_trunc(str(ex.get('extracted_data')), 800)}`\n"
               if ex.get("extracted_data") else "")
            + (f"- Out-of-band callback: `{ex.get('callback_id')}`\n" if ex.get("callback_id") else "")
        )
        if ex.get("request_raw"):
            parts.append("Confirmation request:\n\n```http\n" + _trunc(ex["request_raw"], _EVIDENCE_CAP) + "\n```\n")
    if len(parts) == 1:
        parts.append("_No raw request/response was recorded for this finding (passive detection)._\n")
    return "\n".join(parts)


def _compliance(ctx: dict) -> str:
    return (
        "## 7. Compliance & Framework Mapping\n\n"
        "Each finding in Section 4 is individually mapped to OWASP Top 10 (2021), CWE, PCI-DSS, "
        "NIST CSF, and MITRE ATT&CK / D3FEND. Section 3.3 summarises OWASP coverage. A MITRE "
        "ATT&CK Navigator layer (heat-mapped by finding count) can be exported with "
        "`orthrus report --format navigator` for visualisation on the ATT&CK matrix.\n"
    )


def _appendices(ctx: dict) -> str:
    return (
        "## 8. Appendices\n\n"
        "### Appendix A — Assessment Platform\n"
        "Findings were produced by the ORTHRUS automated assessment platform: a scope-enforced, "
        "async DAST engine with 58 vulnerability scanners, 16 reconnaissance modules, and 17 "
        "exploitation-confirmation modules, with CVSS v3.1/v4.0 scoring and multi-framework "
        "compliance mapping.\n\n"
        "### Appendix B — Severity & Confidence Definitions\n"
        "- **Confidence — confirmed:** re-proven by active, non-destructive exploitation.\n"
        "- **Confidence — firm:** strong signal from a reliable detector; not separately re-proven.\n"
        "- **Confidence — tentative:** indicative signal warranting manual verification.\n\n"
        "### Appendix C — Glossary\n"
        "CVSS — Common Vulnerability Scoring System · CWE — Common Weakness Enumeration · "
        "EPSS — Exploit Prediction Scoring System · OOB — out-of-band.\n"
    )


# --------------------------------------------------------------------------
# LLM narrative (grounded, best-effort)
# --------------------------------------------------------------------------

def _finding_prompt(f: dict) -> str:
    ev = f.get("evidence") or {}
    evidence = "\n".join(
        s for s in [
            f"matched_at: {ev.get('matched_at')}" if ev.get("matched_at") else "",
            f"request:\n{_trunc(ev.get('request_raw'), _LLM_EVIDENCE_CAP)}" if ev.get("request_raw") else "",
            f"response:\n{_trunc(ev.get('response_raw'), _LLM_EVIDENCE_CAP)}" if ev.get("response_raw") else "",
        ] if s
    )
    expl = "; ".join(
        f"{e.get('technique')} success={e.get('success')} data={_trunc(str(e.get('extracted_data')), 300)}"
        for e in (f.get("exploitations") or [])
    )
    return (
        "Write the narrative for the following finding. Produce EXACTLY these Markdown "
        "subsections, each with a #### heading and one to three detailed paragraphs:\n"
        "#### Technical Description\n#### Business Impact\n#### Likelihood of Exploitation\n"
        "#### Exploitation Walkthrough\n#### Remediation\n\n"
        "Ground the Exploitation Walkthrough in the recorded evidence below; step through how an "
        "attacker would abuse this. Make Remediation specific and actionable.\n\n"
        "FINDING:\n"
        f"- Title: {f.get('title')}\n- Type: {f.get('vuln_type')}\n- Severity: {f.get('severity')} "
        f"(CVSS {f.get('cvss_score')})\n- CWE: {f.get('cwe')}\n- OWASP: {f.get('owasp')}\n"
        f"- URL: {f.get('url')}\n- Parameter: {f.get('parameter')}\n"
        f"- Scanner description: {_trunc(f.get('description'), 1200)}\n"
        f"- Existing remediation note: {_trunc(f.get('remediation'), 800)}\n"
        f"- Exploitation confirmation: {expl or 'none recorded'}\n\n"
        f"RECORDED EVIDENCE:\n{evidence or '(no raw request/response recorded)'}"
    )


def _exec_prompt(ctx: dict) -> str:
    summ = ctx["summary"]
    top = "\n".join(
        f"- [{_sev_label(f['severity'])}] {f['title']} — {f.get('url')}"
        for f in ctx["findings"][:12]
    )
    return (
        "Write the **Executive Summary** (start directly with prose; no heading). Cover, in "
        "4–8 paragraphs: the overall security posture and an overall risk rating; the business "
        "context and what a realistic compromise would mean for the organisation; the most "
        "significant findings (reference them by title and severity); systemic themes or root "
        "causes across findings; and prioritised strategic recommendations. Board-readable but "
        "precise.\n\n"
        f"SCAN SUMMARY: {summ['total']} findings, {summ['confirmed']} confirmed by exploitation; "
        f"severity counts {summ['counts']}.\n\nMOST SIGNIFICANT FINDINGS:\n{top}"
    )


def _roadmap_prompt(ctx: dict) -> str:
    lines = "\n".join(
        f"- [{_sev_label(f['severity'])}] {f['title']} (`{f['vuln_type']}`)"
        for f in ctx["findings"][:40]
    )
    return (
        "Write a **Strategic Remediation Roadmap** as three phased subsections with #### headings: "
        "'Immediate (0–30 days)', 'Short-term (30–90 days)', and 'Strategic (90+ days)'. Under "
        "each, list concrete remediation actions grounded in the findings below, with a short "
        "rationale and the risk each action retires. Order by leverage — fixes that break attack "
        "chains or clear critical/high findings come first.\n\n"
        f"FINDINGS:\n{lines}"
    )


def _chain_prompt(chain: dict) -> str:
    steps = " → ".join(f"{s.get('label')} ({s.get('vuln_type')})" for s in (chain.get("steps") or []))
    return (
        "Narrate the following correlated attack chain as a concise, realistic attacker story "
        "(1–2 paragraphs): how an adversary walks the steps to reach the stated impact, and why "
        "breaking any single link defeats it.\n\n"
        f"CHAIN: {chain.get('name')} (severity {chain.get('severity')})\n"
        f"STEPS: {steps}\nIMPACT: {chain.get('impact')}"
    )


async def _narrate(client: LLMClient | None, prompt: str, *, fallback: str, dry_run: bool,
                   max_tokens: int = 1600) -> str:
    if dry_run or client is None:
        return fallback
    try:
        text = (await client.complete(SYSTEM_PROMPT, prompt, max_tokens=max_tokens)).strip()
        return text or fallback
    except LLMError as exc:
        logger.warning("narrative generation failed, using deterministic fallback: %s", exc)
        return fallback


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

async def write_consultant_report(
    ctx: dict, client: LLMClient | None, *, max_detailed: int = 60, dry_run: bool = False,
    log: Callable[[str], None] | None = None,
) -> str:
    """Assemble the full Markdown consultant report (deterministic facts + LLM narrative)."""
    def _log(msg: str) -> None:
        if log:
            log(msg)

    findings = sorted(
        ctx["findings"], key=lambda f: (-_SEV_ORDER.get(f["severity"], 0), f["vuln_type"])
    )
    parts: list[str] = [_cover(ctx)]

    _log("executive summary")
    exec_fb = (
        "_Executive summary narrative is generated by the AI report writer; run without "
        "`--dry-run` (with a configured model) to populate it._"
        if dry_run else
        f"The assessment identified {ctx['summary']['total']} findings "
        f"({ctx['summary']['confirmed']} confirmed by exploitation). See Section 4 for detail."
    )
    parts.append("## 1. Executive Summary\n\n" + await _narrate(
        client, _exec_prompt(ctx), fallback=exec_fb, dry_run=dry_run, max_tokens=2000))

    parts.append(_methodology(ctx))
    parts.append(_overview(ctx))

    parts.append("## 4. Detailed Findings\n")
    for i, f in enumerate(findings, 1):
        _log(f"finding {i}/{len(findings)}: {f['title']}")
        block = [_finding_metadata(f, i)]
        if i <= max_detailed:
            narrative_fb = (
                "_Per-finding narrative (description, business impact, likelihood, exploitation "
                "walkthrough, remediation) is AI-generated; run without `--dry-run` to populate._"
                if dry_run else _trunc(f.get("description"), 1500) + "\n\n**Remediation.** "
                + _trunc(f.get("remediation"), 1200)
            )
            block.append(await _narrate(client, _finding_prompt(f), fallback=narrative_fb,
                                        dry_run=dry_run, max_tokens=1800))
        else:
            block.append(_trunc(f.get("description"), 800) + "\n\n**Remediation.** "
                         + _trunc(f.get("remediation"), 600))
        block.append(_evidence_block(f))
        parts.append("\n".join(block))

    chains = ctx.get("chains") or []
    if chains:
        parts.append("## 5. Correlated Attack Chains\n")
        for i, ch in enumerate(chains, 1):
            _log(f"attack chain {i}/{len(chains)}")
            steps = " → ".join(
                f"{s.get('label')} (`{s.get('vuln_type')}`)" for s in (ch.get("steps") or []))
            header = (
                f"### 5.{i} [{_sev_label(ch.get('severity', 'high'))}] {ch.get('name')}\n\n"
                f"**Path:** {steps}  \n**Impact:** {ch.get('impact')}\n"
            )
            story = await _narrate(client, _chain_prompt(ch),
                                   fallback="_Attack-chain narrative is AI-generated._" if dry_run
                                   else f"An attacker can chain: {steps}.",
                                   dry_run=dry_run, max_tokens=900)
            parts.append(header + "\n" + story)

    _log("remediation roadmap")
    roadmap_fb = ("_Remediation roadmap is AI-generated; run without `--dry-run` to populate._"
                  if dry_run else "Prioritise remediation of critical and high findings, then "
                  "medium, then low; see per-finding remediation in Section 4.")
    parts.append("## 6. Strategic Remediation Roadmap\n\n" + await _narrate(
        client, _roadmap_prompt(ctx), fallback=roadmap_fb, dry_run=dry_run, max_tokens=1800))

    parts.append(_compliance(ctx))
    parts.append(_appendices(ctx))
    _log("done")
    return "\n\n".join(parts) + "\n"


__all__ = ["write_consultant_report", "SYSTEM_PROMPT"]
