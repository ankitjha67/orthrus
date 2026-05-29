"""Headless browser engine (PRD §9).

Wraps Playwright/Chromium to render JS-heavy pages, execute payloads in a real
DOM, capture dialogs, and take evidence screenshots. Every browser request is
filtered through the scope validator via route interception, so the safety
boundary holds even for subresource loads.

Playwright is optional (the [browser] extra). If it's not installed,
``BrowserManager.is_available()`` is False and all browser-dependent scanners /
confirmations self-disable.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeValidator

logger = get_logger("browser")

try:
    from playwright.async_api import async_playwright
except ImportError:  # part of the optional [browser] extra
    async_playwright = None  # type: ignore[assignment]


@dataclass
class ExecutionProbe:
    executed: bool
    marker: str
    method: str = ""  # "global" | "dialog"
    message: str = ""
    screenshot_path: str | None = None


@dataclass
class CapturedRequest:
    """An API request the page fired (XHR/fetch), recorded for the inventory."""

    method: str
    url: str
    post_data: str | None = None
    content_type: str | None = None
    resource_type: str = ""


class BrowserManager:
    def __init__(
        self,
        scope: ScopeValidator,
        *,
        headless: bool = True,
        user_agent: str | None = None,
        screenshot_dir: str = "scan_data/screenshots",
        max_pages_per_context: int = 20,
        nav_timeout_ms: int = 15000,
        har_path: str | None = None,
    ) -> None:
        self.scope = scope
        self.headless = headless
        self.user_agent = user_agent
        self.screenshot_dir = screenshot_dir
        self.max_pages_per_context = max_pages_per_context
        self.nav_timeout_ms = nav_timeout_ms
        self.har_path = har_path
        self.har_files: list[str] = []
        self._har_index = 0
        self._pw = None
        self._browser = None
        self._context = None
        self._page_count = 0
        # API requests (XHR/fetch) observed in-scope, harvested by browser-crawl recon.
        self.captured: list[CapturedRequest] = []
        self._capture_seen: set[tuple[str, str, str, str]] = set()
        self.max_captured = 500

    @staticmethod
    def is_available() -> bool:
        return async_playwright is not None

    async def start(self) -> None:
        if not self.is_available():
            raise RuntimeError("Playwright is not installed ([browser] extra)")
        os.makedirs(self.screenshot_dir, exist_ok=True)
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self.headless)
        await self._new_context()
        logger.info("headless browser engine started (Chromium)")

    async def _new_context(self) -> None:
        if self._context is not None:
            await self._context.close()
        kwargs = {"ignore_https_errors": True}
        if self.user_agent:
            kwargs["user_agent"] = self.user_agent
        if self.har_path:  # one HAR per context (PRD §7.3 evidence)
            self._har_index += 1
            har_file = f"{self.har_path}.{self._har_index}.har"
            kwargs["record_har_path"] = har_file
            self.har_files.append(har_file)
        self._context = await self._browser.new_context(**kwargs)
        await self._context.route("**/*", self._route)
        self._page_count = 0

    async def _route(self, route) -> None:  # type: ignore[no-untyped-def]
        try:
            if self.scope.is_allowed(route.request.url):
                self._maybe_capture(route.request)
                await route.continue_()
            else:
                await route.abort()
        except Exception:
            try:
                await route.abort()
            except Exception:
                pass

    def _maybe_capture(self, request) -> None:  # type: ignore[no-untyped-def]
        """Record in-scope API calls (XHR/fetch, or any body-bearing request)."""
        try:
            method = (request.method or "GET").upper()
            rtype = request.resource_type or ""
            post = request.post_data
            if rtype not in ("xhr", "fetch") and method in ("GET", "HEAD", "OPTIONS") and not post:
                return  # ordinary navigation/subresource, not an API call
            if len(self.captured) >= self.max_captured:
                return
            headers = request.headers or {}
            ctype = headers.get("content-type", "") or ""
            sig = (method, urlsplit(request.url).path, ctype.split(";")[0], post or "")
            if sig in self._capture_seen:
                return
            self._capture_seen.add(sig)
            self.captured.append(
                CapturedRequest(
                    method=method,
                    url=request.url,
                    post_data=post,
                    content_type=ctype or None,
                    resource_type=rtype,
                )
            )
        except Exception:
            pass

    async def _new_page(self):  # type: ignore[no-untyped-def]
        if self._page_count >= self.max_pages_per_context:
            await self._new_context()  # recycle to bound memory (PRD §18 risk)
        self._page_count += 1
        return await self._context.new_page()

    async def render(self, url: str, *, wait_ms: int = 800) -> str | None:
        """Return fully-rendered HTML after JS execution, or None on failure."""
        page = await self._new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
            await page.wait_for_timeout(wait_ms)
            return await page.content()
        except Exception as exc:
            logger.debug("render failed for %s: %s", url, exc)
            return None
        finally:
            await page.close()

    async def evaluate_on(self, url: str, expression: str, *, wait_ms: int = 600):  # type: ignore[no-untyped-def]
        """Navigate to ``url`` then evaluate a JS expression; return its value or None."""
        page = await self._new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
            await page.wait_for_timeout(wait_ms)
            return await page.evaluate(expression)
        except Exception as exc:
            logger.debug("evaluate_on failed for %s: %s", url, exc)
            return None
        finally:
            await page.close()

    async def check_execution(
        self,
        url: str,
        marker: str,
        *,
        screenshot_name: str | None = None,
        wait_ms: int = 700,
    ) -> ExecutionProbe:
        """Navigate to ``url`` and detect whether our payload executed JS.

        Execution is proven by the page setting ``window.__orthrus_xss`` to the
        marker, or by an alert/confirm dialog containing the marker.
        """
        page = await self._new_page()
        dialog_messages: list[str] = []

        def on_dialog(dialog) -> None:  # type: ignore[no-untyped-def]
            dialog_messages.append(dialog.message)
            asyncio.create_task(dialog.dismiss())

        page.on("dialog", on_dialog)
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
            await page.wait_for_timeout(wait_ms)
            try:
                flag = await page.evaluate(f"() => window['__hx_{marker}'] === 1")
            except Exception:
                flag = False

            via_global = bool(flag)
            via_dialog = any(marker in m for m in dialog_messages)
            executed = via_global or via_dialog
            method = "global" if via_global else ("dialog" if via_dialog else "")

            shot = None
            if executed and screenshot_name:
                shot = os.path.join(self.screenshot_dir, f"{screenshot_name}.png")
                try:
                    await page.screenshot(path=shot, full_page=True)
                except Exception:
                    shot = None
            message = dialog_messages[0] if dialog_messages else ""
            return ExecutionProbe(executed, marker, method, message, shot)
        except Exception as exc:
            logger.debug("execution probe failed for %s: %s", url, exc)
            return ExecutionProbe(False, marker)
        finally:
            await page.close()

    async def stop(self) -> None:
        try:
            if self._context is not None:
                await self._context.close()
            if self._browser is not None:
                await self._browser.close()
            if self._pw is not None:
                await self._pw.stop()
        except Exception:
            pass


__all__ = ["BrowserManager", "ExecutionProbe", "CapturedRequest"]
