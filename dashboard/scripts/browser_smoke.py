"""Run browser checks against disposable local services; no external APIs."""

import argparse
import json
import os
import secrets
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]


class FixtureHandler(BaseHTTPRequestHandler):
    available = True

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if not self.available:
            self.send_response(503)
            self.end_headers()
            return
        url = urlsplit(self.path)
        incidents = [
            {
                "incident_id": f"incident-{index}",
                "created_at": "2026-11-09T09:00:00Z",
                "pattern": "same-source-burst",
                "window_seconds": 60,
                "correlated_event_ids": ["e-1"],
                "mitre_techniques": ["T1195.001"],
                "severity": "high" if index == 0 else "medium",
                "confidence": 0.5,
                "summary": '<img src=x onerror="window.untrustedExecuted=true">'
                if index == 0
                else f"Fixture incident {index}",
            }
            for index in range(21)
        ]
        if url.path.endswith("/events"):
            payload = [
                {
                    "event_id": "e-1",
                    "timestamp": "2026-11-09T09:00:00Z",
                    "source": "fixture",
                    "event_type": "attack_scenario_run",
                    "details": {
                        "scenario": "malicious-dependency",
                        "tool_output_tail": "private-tool-output",
                    },
                }
            ]
        elif url.path == "/incidents":
            params = parse_qs(url.query)
            items = incidents
            if "severity" in params:
                items = [
                    item for item in items if item["severity"] == params["severity"][0]
                ]
            if "pattern" in params:
                items = [
                    item for item in items if item["pattern"] == params["pattern"][0]
                ]
            limit = int(params.get("limit", [20])[0])
            offset = int(params.get("offset", [0])[0])
            payload = {
                "total": len(items),
                "limit": limit,
                "offset": offset,
                "items": items[offset : offset + limit],
            }
        else:
            payload = incidents[int(url.path.rsplit("-", 1)[1])]
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        default=str(ROOT / "range/.venv/bin/python"),
        help="Interpreter with dashboard dependencies",
    )
    parser.add_argument(
        "--screenshots",
        type=Path,
        help="Optional directory for desktop and mobile screenshots",
    )
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler) as upstream:
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        token = secrets.token_urlsafe(32)
        environment = {
            **os.environ,
            "DASHBOARD_TOKEN": token,
            "DASHBOARD_ORIGIN": origin,
            "DETECTION_ENGINE_URL": f"http://127.0.0.1:{upstream.server_port}",
            "DASHBOARD_POLL_SECONDS": "1",
        }
        process = subprocess.Popen(
            [
                args.python,
                "-m",
                "uvicorn",
                "bantis_dashboard.main:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--loop",
                "asyncio",
                "--log-level",
                "error",
                "--no-access-log",
            ],
            cwd=ROOT / "dashboard",
            env=environment,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urlopen(origin + "/health", timeout=1) as response:
                        assert response.status == 200
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Disposable dashboard did not start"
                        ) from None
                    time.sleep(0.1)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1100})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(origin)
                page.get_by_label("Dashboard access token").fill("wrong")
                page.get_by_role("button", name="Open dashboard").click()
                expect(page.locator("#login-error")).to_contain_text(
                    "Invalid dashboard access token"
                )
                page.get_by_label("Dashboard access token").fill(token)
                page.get_by_role("button", name="Open dashboard").click()
                expect(page.locator("#incident-rows tr")).to_have_count(20)
                expect(page.locator("#connection-label")).to_have_text(
                    "Live connection · periodic updates"
                )
                expect(page.locator("#total-incidents")).to_have_text("21")
                assert page.evaluate("window.untrustedExecuted") is None
                assert page.locator("#incident-rows img").count() == 0
                page.locator("#next").click()
                expect(page.locator("#page-label")).to_have_text(
                    "21–21 of 21 matching incidents"
                )
                page.locator("#previous").click()
                expect(page.locator("#incident-rows tr")).to_have_count(20)
                page.locator("#severity").select_option("high")
                page.get_by_role("button", name="Apply filters").click()
                expect(page.locator("#incident-rows tr")).to_have_count(1)
                page.locator(".incident-link").click()
                expect(page.locator("#detail-notice")).to_contain_text(
                    "Selected evidence fields"
                )
                expect(page.locator("#detail-content")).to_contain_text(
                    "malicious-dependency"
                )
                assert (
                    "private-tool-output"
                    not in page.locator("#detail-content").inner_text()
                )
                page.get_by_role("button", name="Close ×").click()
                page.locator("#pattern").fill("missing-pattern")
                page.get_by_role("button", name="Apply filters").click()
                expect(page.locator("#list-notice")).to_have_text(
                    "No incidents match these filters."
                )
                page.get_by_role("button", name="Reset", exact=True).click()
                expect(page.locator("#incident-rows tr")).to_have_count(20)
                if args.screenshots:
                    args.screenshots.mkdir(parents=True, exist_ok=True)
                    page.screenshot(
                        path=str(args.screenshots / "dashboard-desktop.png"),
                        full_page=True,
                    )
                FixtureHandler.available = False
                expect(page.locator("#engine-status")).to_have_text(
                    "Unavailable", timeout=10000
                )
                expect(page.locator("#list-notice")).to_contain_text(
                    "Showing stale data", timeout=10000
                )
                expect(page.locator("#incident-rows tr")).to_have_count(20)
                expect(page.locator("#total-incidents")).to_have_text("21")
                FixtureHandler.available = True
                expect(page.locator("#engine-status")).to_have_text(
                    "Available", timeout=10000
                )
                page.evaluate("state.socket.close()")
                expect(page.locator("#connection-label")).to_have_text(
                    "Live connection · periodic updates", timeout=10000
                )
                page.set_viewport_size({"width": 390, "height": 844})
                expect(
                    page.get_by_role("heading", name="Environment overview.")
                ).to_be_visible()
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                )
                if args.screenshots:
                    page.screenshot(
                        path=str(args.screenshots / "dashboard-mobile.png"),
                        full_page=True,
                    )
                page.get_by_role("button", name="Sign out").click()
                expect(page.locator("#login-screen")).to_be_visible()
                expect(page.locator("#incident-rows tr")).to_have_count(0)
                assert not errors, errors
                browser.close()
                print(
                    "PASS: login, live updates, pagination, filters, empty results, evidence, untrusted text, stale data, reconnect, mobile layout, and logout"
                )
        finally:
            process.terminate()
            process.wait(timeout=5)
            upstream.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()