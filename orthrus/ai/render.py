"""Render the consultant Markdown report to a styled, self-contained HTML document.

Clients receive PDF/HTML deliverables, not Markdown. This is a small hand-rolled
renderer for the exact Markdown subset the report writer emits (headings, tables,
fenced code, lists, blockquotes, rules, bold/italic/code/link inlines) — no new
dependency. The HTML shell carries an inline Big-Four-style stylesheet with print
page-breaks so `orthrus.reporting.pdf.html_to_pdf` (headless Chromium) turns it
into a paginated PDF.
"""

from __future__ import annotations

import re

_SEP_RE = re.compile(r":?-{2,}:?")
_HEADING_RE = re.compile(r"(#{1,6})\s+(.*)$")
_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC_RE = re.compile(r"(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])")
_SPECIAL_PREFIX = ("#", "|", "```", ">", "- ", "* ", "---", "***", "___")


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline(text: str) -> str:
    """Escape, then apply inline Markdown (code first so its content is left alone)."""
    t = _escape(text)
    t = _CODE_RE.sub(r"<code>\1</code>", t)
    t = _LINK_RE.sub(r'<a href="\2">\1</a>', t)
    t = _BOLD_RE.sub(r"<strong>\1</strong>", t)
    t = _ITALIC_RE.sub(r"<em>\1</em>", t)
    return t


def _split_row(row: str) -> list[str]:
    row = row.strip()
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|"):
        row = row[:-1]
    return [c.strip() for c in row.split("|")]


def _is_table_sep(line: str) -> bool:
    s = line.strip()
    if not s.startswith("|"):
        return False
    cells = [c for c in _split_row(s) if c]
    return bool(cells) and all(_SEP_RE.fullmatch(c) for c in cells)


def _render_table(header: list[str], rows: list[list[str]]) -> str:
    width = len(header)
    thead = "".join(f"<th>{_inline(c)}</th>" for c in header)
    body = []
    for r in rows:
        cells = (r + [""] * width)[:width]
        body.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
    return f"<table>\n<thead><tr>{thead}</tr></thead>\n<tbody>{''.join(body)}</tbody>\n</table>"


def _render_body(md: str) -> str:  # noqa: C901 — a small, linear block dispatcher
    lines = md.split("\n")
    n = len(lines)
    out: list[str] = []
    in_list = False
    i = 0

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            close_list()
            i += 1
            code: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1  # consume closing fence
            out.append(f"<pre><code>{_escape(chr(10).join(code))}</code></pre>")
            continue

        if stripped.startswith("|") and i + 1 < n and _is_table_sep(lines[i + 1]):
            close_list()
            header = _split_row(stripped)
            i += 2
            rows: list[list[str]] = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(_split_row(lines[i]))
                i += 1
            out.append(_render_table(header, rows))
            continue

        heading = _HEADING_RE.match(stripped)
        if heading:
            close_list()
            level = len(heading.group(1))
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            i += 1
            continue

        if stripped in ("---", "***", "___"):
            close_list()
            out.append("<hr/>")
            i += 1
            continue

        if stripped.startswith(">"):
            close_list()
            out.append(f"<blockquote>{_inline(stripped.lstrip('>').strip())}</blockquote>")
            i += 1
            continue

        if stripped.startswith(("- ", "* ")):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
            i += 1
            continue

        if not stripped:
            close_list()
            i += 1
            continue

        # paragraph: gather consecutive plain lines, honouring 2-space hard breaks
        close_list()
        segs = [stripped]
        breaks = [line.endswith("  ")]
        i += 1
        while i < n:
            raw = lines[i]
            nxt = raw.strip()
            if not nxt or nxt.startswith(_SPECIAL_PREFIX):
                break
            segs.append(nxt)
            breaks.append(raw.endswith("  "))
            i += 1
        buf: list[str] = []
        for idx, seg in enumerate(segs):
            buf.append(_inline(seg))
            if idx < len(segs) - 1:
                buf.append("<br/>\n" if breaks[idx] else " ")
        out.append("<p>" + "".join(buf) + "</p>")

    close_list()
    return "\n".join(out)


_CSS = """
:root { --ink:#1a1a1a; --muted:#666666; --line:#e2e2e2; --accent:#c40000;
        --crit:#a10000; --high:#c0392b; --med:#8a3a3a; --low:#555555; --code:#f5f5f5; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif; color: var(--ink);
       line-height: 1.55; margin: 0; font-size: 11pt; }
main { max-width: 860px; margin: 0 auto; padding: 32px 40px 64px; }
h1 { font-size: 30pt; color: var(--accent); border-bottom: 3px solid var(--accent);
     padding-bottom: 10px; margin: 8px 0 18px; }
h2 { font-size: 18pt; color: var(--accent); border-bottom: 1px solid var(--line);
     padding-bottom: 5px; margin: 34px 0 14px; page-break-before: always; }
h1 + * , h2:first-of-type { page-break-before: auto; }
h3 { font-size: 14pt; color: #8a0000; margin: 22px 0 8px; }
h4 { font-size: 11.5pt; color: var(--muted); text-transform: uppercase;
     letter-spacing: .04em; margin: 16px 0 6px; }
p { margin: 8px 0; }
a { color: var(--accent); text-decoration: none; }
ul { margin: 8px 0 8px 22px; }
li { margin: 3px 0; }
hr { border: 0; border-top: 1px solid var(--line); margin: 20px 0; }
blockquote { margin: 12px 0; padding: 8px 16px; border-left: 4px solid var(--accent);
             background: #f7f7f7; color: var(--muted); }
code { background: var(--code); border: 1px solid var(--line); border-radius: 3px;
       padding: 1px 5px; font-family: "Cascadia Code", Consolas, monospace; font-size: 9.5pt; }
pre { background: var(--code); border: 1px solid var(--line); border-radius: 5px;
      padding: 12px 14px; overflow-x: auto; page-break-inside: avoid; }
pre code { background: none; border: 0; padding: 0; white-space: pre; font-size: 9pt;
           line-height: 1.4; }
table { border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 9.8pt;
        page-break-inside: avoid; }
th, td { border: 1px solid var(--line); padding: 6px 9px; text-align: left; vertical-align: top; }
th { background: var(--accent); color: #fff; font-weight: 600; }
tbody tr:nth-child(even) { background: #f7f7f7; }
@page { size: A4; margin: 18mm 16mm; }
@media print { h2 { page-break-before: always; } main { padding: 0; max-width: none; } }
"""

_BANNER = ('<div style="background:#8b1a1a;color:#fff;text-align:center;'
           'font-size:9pt;letter-spacing:.12em;padding:5px;text-transform:uppercase;">'
           'Confidential — Penetration Test Report</div>')


def markdown_to_html(md: str, title: str = "Penetration Test Report") -> str:
    """Turn the consultant Markdown into one self-contained, print-ready HTML string."""
    body = _render_body(md)
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\"/>\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\n"
        f"<title>{_escape(title)}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n"
        f"{_BANNER}\n<main>\n{body}\n</main>\n</body>\n</html>\n"
    )


__all__ = ["markdown_to_html"]
