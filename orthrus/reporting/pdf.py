"""HTML -> PDF rendering via headless Chromium (reuses the [browser] extra).

Avoids WeasyPrint/GTK native dependencies (painful on Windows) by printing the
report HTML with Playwright's Chromium. Returns False if Playwright is absent.
"""

from __future__ import annotations

import os

from orthrus.utils.logger import get_logger

logger = get_logger("reporting.pdf")

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None  # type: ignore[assignment]


def _file_url(html_path: str) -> str:
    return "file:///" + os.path.abspath(html_path).replace("\\", "/")


async def html_to_pdf(html_path: str, pdf_path: str) -> bool:
    if async_playwright is None:
        return False
    file_url = _file_url(html_path)
    try:
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(file_url, wait_until="networkidle")
            await page.pdf(path=pdf_path, format="A4", print_background=True)
        finally:
            await browser.close()
            await pw.stop()
        return True
    except Exception as exc:
        logger.debug("PDF rendering failed: %s", exc)
        return False


__all__ = ["html_to_pdf"]
