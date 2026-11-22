"""One document, one browser, no credentials and no external network."""

from __future__ import annotations

import os
import socket
import sys

from weir.browser.linux_report import receive_message, send_message
from weir.review_board import MAX_HTML, ROW_LIMIT, validate_board_url


def run(sock):
    from playwright.sync_api import sync_playwright

    for family in (socket.AF_INET, socket.AF_INET6):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            try:
                test = socket.socket(family, kind)
            except OSError:
                continue
            test.close()
            raise OSError("The browser service can open an Internet socket.")
    sock.settimeout(45)
    sock.sendall(b"W")
    with sock.makefile("rb") as reader:
        command = receive_message(reader)
        url = command.get("url")
        validate_board_url(url)
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                context = browser.new_context(java_script_enabled=False, service_workers="block",
                                              accept_downloads=False)
                page = context.new_page()
                requested = False

                def handle(route):
                    nonlocal requested
                    request = route.request
                    if (requested or request.url != url or request.method != "GET"
                            or not request.is_navigation_request() or request.frame != page.main_frame):
                        return route.abort()
                    requested = True
                    try:
                        send_message(sock, {"read": url})
                        html = receive_message(reader).get("html")
                    except (OSError, ValueError):
                        return route.abort()
                    if not isinstance(html, str) or len(html.encode("utf-8")) > MAX_HTML:
                        return route.abort()
                    route.fulfill(status=200, headers={"content-type": "text/html; charset=utf-8",
                                  "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'none'"},
                                  body=html)

                context.route("**/*", handle)
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                board = page.locator('main[data-weir-review-board="1"]')
                if not requested or page.url != url or board.count() != 1:
                    raise ValueError("The authenticated Review column is missing.")
                total = int(board.get_attribute("data-total"))
                workspace = int(board.get_attribute("data-workspace-id"))
                rows = board.locator("li[data-task-id]")
                if total < 0 or rows.count() != min(ROW_LIMIT, total):
                    raise ValueError("Incomplete review column.")
                tasks = rows.evaluate_all("""rows => rows.map(row => {
                    const titles = row.querySelectorAll('span[data-task-title]');
                    if (titles.length !== 1) throw Error('Invalid task title');
                    return { id: Number(row.dataset.taskId), title: titles[0].textContent };
                })""")
                send_message(sock, {"result": {"workspace": workspace, "total": total, "tasks": tasks}})
                if receive_message(reader) != {"finish": True}:
                    raise OSError("The report observation was interrupted.")
            finally:
                browser.close()


def main():
    try:
        with socket.socket(fileno=os.dup(0)) as sock:
            run(sock)
    except Exception as exc:
        # Browser/HTTP exceptions can include private content. Keep it out of the journal.
        print("Review browser stopped: " + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
