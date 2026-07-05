"""Hand-rolled Markdown -> styled HTML renderer for the consultant deliverable."""

from __future__ import annotations

import asyncio

from orthrus.ai.render import markdown_to_html
from orthrus.ai.report_writer import write_consultant_report
from tests.unit.test_ai_report import _ctx, _FakeClient


def test_headings_paragraphs_and_shell():
    html = markdown_to_html("# Title\n\nHello world.\n\n## Section\n\nBody.", title="T")
    assert "<!DOCTYPE html>" in html and "<style>" in html  # self-contained
    assert "<h1>Title</h1>" in html and "<h2>Section</h2>" in html
    assert "<p>Hello world.</p>" in html
    assert "<title>T</title>" in html


def test_table_renders_and_drops_pipes():
    md = "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |"
    html = markdown_to_html(md)
    assert "<table>" in html and "<th>A</th>" in html and "<td>1</td>" in html
    # no raw markdown pipes leaked into the body
    assert "| A | B |" not in html


def test_inline_bold_link_code_and_escaping():
    html = markdown_to_html(
        "A **bold** and `code` and [ref](http://x/?a=1&b=2), plus <script>alert(1)</script>."
    )
    assert "<strong>bold</strong>" in html
    assert "<code>code</code>" in html
    assert '<a href="http://x/?a=1&amp;b=2">ref</a>' in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # HTML injection neutralised
    assert "<script>" not in html


def test_fenced_code_list_quote_rule():
    md = "```\nGET /x HTTP/1.1\n<b>\n```\n\n- one\n- two\n\n> a note\n\n---"
    html = markdown_to_html(md)
    assert "<pre><code>GET /x HTTP/1.1\n&lt;b&gt;</code></pre>" in html  # verbatim + escaped
    assert "<ul>" in html and "<li>one</li>" in html and "<li>two</li>" in html
    assert "<blockquote>a note</blockquote>" in html
    assert "<hr/>" in html


def test_hard_line_break_preserved():
    html = markdown_to_html("Line one  \nLine two")
    assert "<br/>" in html


def test_real_report_renders_to_clean_html():
    md = asyncio.run(write_consultant_report(_ctx(), _FakeClient()))
    html = markdown_to_html(md, title="Report")
    assert "<h1>Penetration Test Report" in html and "</h1>" in html
    assert "<table>" in html  # findings/remediation tables rendered
    # evidence preserved verbatim inside a code block, HTML-escaped
    assert "GET /item?id=1&#39;-- HTTP/1.1" in html or "GET /item?id=1'-- HTTP/1.1" in html
    # no unrendered block markdown left in the body
    body = html.split("<main>", 1)[1]
    assert "\n## " not in body and "\n#### " not in body
