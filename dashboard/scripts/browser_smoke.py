"""Run browser checks against disposable local services; no external APIs."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]


class FixtureHandler(BaseHTTPRequestHandler):
    available = True
    live_events: ClassVar[list] = []
    analysis_state = "analyzed"
    copilot_available = True
    questions: ClassVar[list] = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if not self.available:
            self.send_response(503)
            self.end_headers()
            return
        url = urlsplit(self.path)
        if url.path.endswith(("/analysis", "/questions")):
            if (
                self.headers.get("Authorization")
                != "Bearer browser-fixture-copilot-token"
            ):
                self.send_error(401)
                return
            if not self.copilot_available:
                self.send_error(503)
                return
            incident_id = url.path.split("/")[2]
            payload = (
                self.questions
                if url.path.endswith("/questions")
                else {
                    "incident_id": incident_id,
                    "status": self.analysis_state,
                    "can_ask": self.analysis_state == "analyzed",
                    "record_id": "record-1",
                    "recorded_at": "2026-11-09T09:00:00Z",
                    "model": "fixture-model",
                    "outcome": "flag_for_review",
                    "note": None,
                    "analysis": {
                        "incident_id": incident_id,
                        "reasoning": '<img src=x onerror="window.untrustedExecuted=true"> Correlated evidence supports review.',
                        "confidence": 0.7,
                        "model": "fixture-model",
                        "generated_at": "2026-11-09T09:00:00Z",
                        "proposed_action": {
                            "type": "flag_for_review",
                            "description": "Investigate these signals.",
                            "requires_approval": True,
                        },
                    }
                    if self.analysis_state in {"analyzed", "failed"}
                    else None,
                }
            )
            self.send_json(payload)
            return
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
        if url.path == "/events":
            limit = int(parse_qs(url.query).get("limit", [500])[0])
            payload = {
                "total": len(self.live_events),
                "limit": limit,
                "items": sorted(
                    self.live_events,
                    key=lambda event: (event["received_at"], event["event_id"]),
                    reverse=True,
                )[:limit],
            }
        elif url.path.endswith("/events"):
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

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer browser-fixture-copilot-token":
            self.send_error(401)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        record = {
            "followup_id": f"question-{len(self.questions) + 1}",
            "incident_id": self.path.split("/")[2],
            "asked_at": "2026-11-09T10:00:00Z",
            "question": body["question"],
            "answer": "Review the evidence timeline first.",
            "model": "fixture-model",
        }
        self.questions.append(record)
        self.send_json(record, 201)


def seed_response_queue(python, state_dir, environment):
    secret = state_dir / "approver-secret"
    secret.write_text("browser-operator-secret")
    secret.chmod(0o600)
    environment.update({
        "DASHBOARD_RESPONSE_ENABLED": "true",
        "BANTIS_STATE_DIR": str(state_dir),
        "RESPONSE_APPROVER_SECRET_FILE": str(secret),
        "RESPONSE_ENABLED_ACTIONS": "lift_promotion_hold",
        "RESPONSE_DRY_RUN": "true",
        "RESPONSE_AUTO_ACTION": "",
        "RESPONSE_AUTO_REPO": "",
        "RESPONSE_GITHUB_REPO": "",
        "RESPONSE_GITHUB_TOKEN_PROMOTION": "",
    })
    now = datetime.now(UTC)
    for action_id in ("act_browser_modify", "act_browser_approve"):
        source = state_dir / "proposal.json"
        source.write_text(json.dumps({
            "action_id": action_id, "incident_id": "incident-0",
            "type": "lift_promotion_hold", "policy_rule": "B3:operator-request",
            "created_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
        }))
        subprocess.run([python, str(ROOT / "response-controller/cli.py"), "propose", str(source)],
                       env=environment, check=True, capture_output=True)


def check_response_review(page):
    forms = page.locator("#response-proposals form")
    expect(forms).to_have_count(2)
    expect(page.locator("#response-notice")).to_contain_text("Dry run")
    viewport = page.viewport_size
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.locator("#incident-dialog").evaluate("el => el.scrollWidth <= el.clientWidth")
    page.set_viewport_size(viewport)
    first = forms.first
    first.get_by_label("Reason").fill("False positive")
    first.get_by_label("Operator approval secret").fill("wrong-secret")
    first.get_by_role("button", name="Dismiss", exact=True).click()
    expect(page.locator("#response-notice")).to_contain_text("Operator authentication failed")
    expect(first.get_by_label("Operator approval secret")).to_have_value("")
    expect(first.get_by_role("button", name="Approve", exact=True)).to_be_disabled()
    page.locator("#response-refresh").click()
    expect(forms.first.get_by_role("button", name="Modify", exact=True)).to_be_enabled()
    first.get_by_label("Reason").fill("Review replacement")
    first.get_by_label("Replacement parameters").fill("invalid JSON")
    first.get_by_label("Operator approval secret").fill("browser-operator-secret")
    first.get_by_role("button", name="Modify", exact=True).click()
    expect(page.locator("#response-notice")).to_contain_text("must be a JSON object")
    first.get_by_label("Replacement parameters").fill("{}")
    first.get_by_role("button", name="Modify", exact=True).click()
    expect(page.locator("#response-notice")).to_contain_text("Controller result: modified")
    expect(forms).to_have_count(2)
    expect(forms.last).not_to_contain_text("act_browser_modify")
    forms.last.get_by_label("Reason").fill("False positive")
    forms.last.get_by_label("Operator approval secret").fill("browser-operator-secret")
    forms.last.get_by_role("button", name="Dismiss", exact=True).click()
    expect(page.locator("#response-notice")).to_contain_text("Controller result: dismissed")
    expect(forms).to_have_count(1)
    forms.first.get_by_label("Operator approval secret").fill("browser-operator-secret")
    forms.first.get_by_role("button", name="Approve", exact=True).click()
    expect(page.locator("#response-notice")).to_contain_text("Controller result: invalidated")
    expect(forms).to_have_count(0)
    expect(page.locator("#response-notice")).to_contain_text("No pending controller proposals")


def check_incidents(page, screenshots):
    page.get_by_role("link", name="Incidents", exact=True).click()
    expect(page.locator('[data-page="incidents"]')).to_have_attribute(
        "aria-current", "page"
    )
    expect(page.get_by_role("heading", name="Incidents.", exact=True)).to_be_visible()
    page.locator("#severity").select_option("high")
    page.get_by_role("button", name="Apply filters").click()
    expect(page.locator("#incident-rows tr")).to_have_count(1)
    page.locator("#incident-rows .incident-link").click()
    expect(page.locator("#analysis-content")).to_contain_text("Analysis recorded")
    expect(page.locator("#analysis-content")).to_contain_text(
        "70% · separate from detection confidence"
    )
    expect(page.locator("#ask-question")).to_be_enabled()
    assert page.locator("#analysis-panel img").count() == 0
    check_response_review(page)
    page.locator("#question").fill("Why review this evidence?")
    page.locator("#ask-question").click()
    expect(page.locator("#conversation")).to_contain_text(
        "Review the evidence timeline first."
    )
    expect(page.locator("#question")).to_have_value("")
    expect(page.locator("#ask-question")).to_be_enabled()
    FixtureHandler.copilot_available = False
    page.locator("#analysis-refresh").click()
    expect(page.locator("#analysis-notice")).to_contain_text("Showing stale analysis")
    expect(page.locator("#analysis-content")).to_contain_text("Analysis recorded")
    expect(page.locator("#ask-question")).to_be_disabled()
    FixtureHandler.copilot_available = True
    for state, label in [
        ("not_recorded", "No analysis recorded"),
        ("skipped", "Analysis skipped"),
        ("failed", "Stored analysis failed"),
    ]:
        FixtureHandler.analysis_state = state
        page.locator("#analysis-refresh").click()
        expect(page.locator("#analysis-content")).to_contain_text(label)
        expect(page.locator("#ask-question")).to_be_disabled()
    FixtureHandler.analysis_state = "analyzed"
    page.locator("#analysis-refresh").click()
    expect(page.locator("#ask-question")).to_be_enabled()
    page.locator("#question").fill("Keep my draft")
    page.locator("#analysis-refresh").click()
    expect(page.locator("#ask-question")).to_be_enabled()
    expect(page.locator("#question")).to_have_value("Keep my draft")
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.locator("#incident-dialog").evaluate("el => el.scrollTop = 0")
    if screenshots:
        page.screenshot(
            path=str(screenshots / "incident-analysis-desktop.png"), full_page=True
        )
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator("#incident-dialog").evaluate("el => el.scrollTop = 0")
    assert page.locator("#incident-dialog").evaluate(
        "el => el.scrollWidth <= el.clientWidth"
    )
    if screenshots:
        page.screenshot(
            path=str(screenshots / "incident-analysis-mobile.png"), full_page=True
        )
    page.keyboard.press("Escape")
    expect(page.locator("#incident-rows tr")).to_have_count(1)
    expect(page.locator("#severity")).to_have_value("high")
    page.locator("#incident-rows .incident-link").click()
    expect(page.locator("#question")).to_have_value("")
    expect(page.locator("#conversation")).to_contain_text("Why review this evidence?")
    page.keyboard.press("Escape")
    assert page.evaluate("window.untrustedExecuted") is None


def check_live_feed(page, screenshots):
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.get_by_role("link", name="Live feed").click()
    expect(page.locator("#live-notice")).to_contain_text("No events received yet")

    def event(number, *, level="INFO", source="pipeline", event_type="http_request"):
        return {
            "event_id": f"event-{number}",
            "timestamp": "2020-01-01T00:00:00Z",
            "received_at": f"2026-11-09T09:{number // 60:02d}:{number % 60:02d}Z",
            "level": level,
            "logger": "fixture",
            "source": source,
            "event_type": event_type,
            "message": "private-message",
            "details": {
                "artifact": '<img src=x onerror="window.untrustedExecuted=true">',
                "tool_output_tail": "private-tool-output",
            },
        }

    FixtureHandler.live_events = [
        event(
            1, level="WARNING", source="attack-sim", event_type="attack_scenario_run"
        ),
        event(2),
    ]
    expect(page.locator("#live-rows tr")).to_have_count(2, timeout=10000)
    expect(page.locator("#live-connection")).to_have_text(
        "Live connection · periodic event updates"
    )
    assert page.locator("#live-rows img").count() == 0
    assert page.evaluate("window.untrustedExecuted") is None
    page.locator("#event-level").select_option("WARNING")
    expect(page.locator("#live-rows tr")).to_have_count(1)
    page.locator("#event-source").fill("absent")
    expect(page.locator("#live-notice")).to_have_text(
        "No events match the current filters."
    )
    page.locator("#event-source").fill("attack-sim")
    page.locator("#event-type").fill("attack_scenario_run")
    expect(page.locator("#live-rows tr")).to_have_count(1)
    page.get_by_role("button", name="Reset filters").click()
    page.locator("#event-search").fill("event-2")
    expect(page.locator("#live-rows tr")).to_have_count(1)
    page.get_by_role("button", name="Reset filters").click()
    expect(page.locator("#live-rows tr")).to_have_count(2)
    page.get_by_role("button", name="Pause display").click()
    FixtureHandler.live_events.append(event(3))
    expect(page.locator("#live-pending")).to_have_text(
        "1 new in current window · resume to display", timeout=10000
    )
    expect(page.locator("#live-rows tr")).to_have_count(2)
    page.get_by_role("button", name="Refresh feed").click()
    expect(page.locator("#live-rows tr")).to_have_count(2)
    page.get_by_role("button", name="Resume display").click()
    expect(page.locator("#live-rows tr")).to_have_count(3)
    expect(page.locator("#live-rows tr").first).to_contain_text("event-3")
    page.locator("#live-rows .incident-link").first.click()
    expect(page.locator("#detail-content")).to_contain_text("2020-01-01")
    assert "private-tool-output" not in page.locator("#detail-content").inner_text()
    assert "private-message" not in page.locator("#detail-content").inner_text()
    assert page.locator("#detail-content img").count() == 0
    page.keyboard.press("Escape")
    if screenshots:
        page.screenshot(path=str(screenshots / "live-feed-desktop.png"), full_page=True)
    page.get_by_role("button", name="Clear view").click()
    expect(page.locator("#live-rows tr")).to_have_count(0)
    sequence = page.evaluate("live.snapshot.sequence")
    page.wait_for_function(
        "sequence => live.snapshot.sequence > sequence", arg=sequence
    )
    expect(page.locator("#live-rows tr")).to_have_count(0)
    FixtureHandler.live_events.append(event(4))
    expect(page.locator("#live-rows tr")).to_have_count(1, timeout=10000)
    FixtureHandler.available = False
    expect(page.locator("#live-mode")).to_have_text("Unavailable", timeout=10000)
    expect(page.locator("#live-notice")).to_contain_text("Showing stale data")
    expect(page.locator("#live-rows tr")).to_have_count(1)
    FixtureHandler.available = True
    expect(page.locator("#live-mode")).to_have_text("Live", timeout=10000)
    page.evaluate("state.socket.close()")
    expect(page.locator("#live-connection")).to_have_text(
        "Live connection · periodic event updates", timeout=10000
    )
    expect(page.locator("#live-rows tr")).to_have_count(1)
    page.set_viewport_size({"width": 390, "height": 844})
    expect(page.get_by_role("heading", name="Live feed.")).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    if screenshots:
        page.screenshot(path=str(screenshots / "live-feed-mobile.png"), full_page=True)
    FixtureHandler.live_events.extend(event(index) for index in range(5, 506))
    expect(page.locator("#live-rows tr")).to_have_count(500, timeout=10000)
    expect(page.locator("#live-gap")).to_be_visible()
    sequence = page.evaluate("live.snapshot.sequence")
    page.wait_for_function(
        "sequence => live.snapshot.sequence > sequence", arg=sequence
    )
    expect(page.locator("#live-rows tr")).to_have_count(500)


def append_audit(path, sequence):
    payload = json.dumps(
        {
            "action_id": f"act_{sequence}",
            "event": "outcome",
            "actor": "executor",
            "initiated_by": "alice",
            "incident_id": f"incident-{sequence % 2}",
            "type": "notify_operator",
            "status": "dry_run",
            "at": "2026-11-10T09:00:00Z",
            "reason": '<img src=x onerror="window.untrustedExecuted=true">',
            "proposal": {"params": {"token": "private-audit-parameter"}},
            "state": {"secret": "private-audit-snapshot"},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, previous_hash TEXT, entry_hash TEXT)"
        )
        row = db.execute(
            "SELECT entry_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = row[0] if row else "0" * 64
        digest = hashlib.sha256(
            f"{sequence}\n{previous}\n{payload}".encode()
        ).hexdigest()
        db.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?)",
            (sequence, payload, previous, digest),
        )


def check_audit_log(page, path, screenshots):
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.get_by_role("link", name="Audit log", exact=True).click()
    expect(page.locator('[data-page="audit-log"]')).to_have_attribute(
        "aria-current", "page"
    )
    expect(page.locator("#audit-rows tr")).to_have_count(20)
    expect(page.locator("#audit-total")).to_have_text("23")
    expect(page.locator("#audit-integrity")).to_have_text("Consistent")
    assert page.evaluate("state.socket === null")
    assert page.locator("#audit-rows tr").first.inner_text().startswith("#23")
    append_audit(path, 24)
    page.locator("#audit-next").click()
    expect(page.locator("#audit-page")).to_have_text(
        "21–23 of 23 matching entries · through sequence 23"
    )
    expect(page.locator("#audit-rows tr")).to_have_count(3)
    page.locator("#audit-refresh").click()
    expect(page.locator("#audit-total")).to_have_text("24")
    expect(page.locator("#audit-rows tr").first).to_contain_text("#24")
    page.locator("#audit-actor").fill("alice")
    page.locator("#audit-action").fill("act_7")
    page.locator("#audit-filters").get_by_role("button", name="Apply filters").click()
    expect(page.locator("#audit-rows tr")).to_have_count(1)
    page.locator("#audit-rows .incident-link").click()
    expect(page.locator("#detail-content")).to_contain_text("act_7")
    expect(page.locator("#detail-content")).to_contain_text("Previous entry hash")
    expect(page.locator("#detail-content")).to_contain_text("<img src=x")
    assert "private-audit" not in page.locator("#detail-content").inner_text()
    assert page.locator("#detail-content img").count() == 0
    page.keyboard.press("Escape")
    expect(page.locator("#audit-action")).to_have_value("act_7")
    expect(page.locator("#audit-rows tr")).to_have_count(1)
    page.locator("#audit-actor").fill("nobody")
    page.locator("#audit-filters").get_by_role("button", name="Apply filters").click()
    expect(page.locator("#audit-notice")).to_have_text(
        "No audit entries match these filters."
    )
    page.locator("#audit-filters").get_by_role("button", name="Reset filters").click()
    expect(page.locator("#audit-rows tr")).to_have_count(20)
    page.locator("#audit-limit").select_option("50")
    page.locator("#audit-filters").get_by_role("button", name="Apply filters").click()
    expect(page.locator("#audit-rows tr")).to_have_count(24)
    with sqlite3.connect(path) as db:
        original = db.execute(
            "SELECT payload FROM events WHERE sequence = 1"
        ).fetchone()[0]
        db.execute("UPDATE events SET payload = '{}' WHERE sequence = 1")
    page.locator("#audit-refresh").click()
    expect(page.locator("#audit-notice")).to_contain_text(
        "Audit integrity check failed"
    )
    expect(page.locator("#audit-notice")).to_contain_text("Showing stale rows")
    expect(page.locator("#audit-integrity")).to_have_text("Not confirmed")
    expect(page.locator("#audit-rows tr")).to_have_count(24)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE events SET payload = ? WHERE sequence = 1", (original,))
    page.locator("#audit-refresh").click()
    expect(page.locator("#audit-integrity")).to_have_text("Consistent")
    moved = path.with_suffix(".unavailable")
    path.rename(moved)
    try:
        page.locator("#audit-refresh").click()
        expect(page.locator("#audit-notice")).to_contain_text(
            "Audit journal is unavailable"
        )
        expect(page.locator("#audit-rows tr")).to_have_count(24)
    finally:
        moved.rename(path)
    page.locator("#audit-refresh").click()
    expect(page.locator("#audit-integrity")).to_have_text("Consistent")
    if screenshots:
        page.screenshot(path=str(screenshots / "audit-log-desktop.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.locator("#audit-rows .incident-link").first.click()
    assert page.locator("#incident-dialog").evaluate(
        "el => el.scrollWidth <= el.clientWidth"
    )
    if screenshots:
        page.screenshot(
            path=str(screenshots / "audit-detail-mobile.png"), full_page=True
        )
    page.keyboard.press("Escape")
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM events")
    page.locator("#audit-refresh").click()
    expect(page.locator("#audit-notice")).to_have_text(
        "The controller journal has no recorded events yet."
    )
    expect(page.locator("#audit-total")).to_have_text("0")
    assert page.evaluate("window.untrustedExecuted") is None


def check_admin_setup(page, origin, token, screenshots):
    password = "browser administrator passphrase"
    expect(page.locator("#setup-screen")).to_be_visible()
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    if screenshots:
        page.screenshot(path=str(screenshots / "admin-setup-mobile.png"), full_page=True)
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.locator("#setup-username").fill("Browser.Admin")
    page.locator("#setup-token").fill(token)
    page.locator("#setup-password").fill(password)
    page.locator("#setup-confirmation").fill("a different passphrase")
    page.locator("#create-admin").click()
    expect(page.locator("#setup-notice")).to_contain_text("Passwords must match")
    page.locator("#setup-confirmation").fill(password)
    page.locator("#setup-token").fill("wrong-bootstrap-token")
    page.locator("#create-admin").click()
    expect(page.locator("#setup-notice")).to_contain_text("Invalid setup bootstrap token")
    expect(page.locator("#setup-username")).to_have_value("Browser.Admin")
    for field in ("#setup-token", "#setup-password", "#setup-confirmation"):
        expect(page.locator(field)).to_have_value("")
    page.locator("#setup-token").fill(token)
    page.locator("#setup-password").fill(password)
    page.locator("#setup-confirmation").fill(password)
    page.locator("#create-admin").click()
    expect(page.locator("#admin-fields")).to_be_visible()
    expect(page.locator("#login-description")).to_contain_text("Administrator created")
    expect(page.locator("#admin-username")).to_have_value("browser.admin")
    page.goto(origin + "/setup")
    expect(page.locator("#setup-screen")).to_be_hidden()
    expect(page.locator("#admin-fields")).to_be_visible()
    page.locator("#admin-username").fill("BROWSER.ADMIN")
    page.locator("#admin-password").fill("incorrect password")
    page.get_by_role("button", name="Open dashboard").click()
    expect(page.locator("#login-error")).to_contain_text("Invalid administrator username or password")
    expect(page.locator("#admin-password")).to_have_value("")
    page.locator("#admin-password").fill(password)
    page.get_by_role("button", name="Open dashboard").click()
    expect(page.locator("#workspace")).to_be_visible()
    page.reload()
    expect(page.locator("#workspace")).to_be_visible()
    assert page.evaluate("localStorage.length + sessionStorage.length") == 0
    check_provider_setup(page, origin)
    page.goto(origin)


def check_provider_setup(page, origin):
    expect(page.locator("#provider-view")).to_be_visible()
    expect(page.locator("#provider-model")).to_be_enabled()
    expect(page.locator("#provider-save")).to_be_disabled()
    page.locator("#provider-key").fill("browser-invalid-provider-key")
    page.locator("#provider-test").click()
    expect(page.locator("#provider-notice")).to_contain_text("rejected the API key")
    expect(page.locator("#provider-key")).to_have_value("")
    expect(page.locator("#provider-save")).to_be_disabled()
    page.locator("#provider-key").fill("browser-fixture-provider-key")
    page.locator("#provider-test").click()
    expect(page.locator("#provider-notice")).to_contain_text("Connection succeeded")
    expect(page.locator("#provider-key")).to_have_value("")
    expect(page.locator("#provider-save")).to_be_enabled()
    page.locator("#provider-model").fill("claude-different-model")
    expect(page.locator("#provider-save")).to_be_disabled()
    page.locator("#provider-key").fill("browser-fixture-provider-key")
    page.locator("#provider-test").click()
    expect(page.locator("#provider-notice")).to_contain_text("Connection succeeded")
    page.locator("#provider-save").click()
    expect(page.locator("#provider-notice")).to_contain_text("Provider saved")
    expect(page.locator("#provider-saved")).to_contain_text("claude-different-model")
    page.reload()
    expect(page.locator("#provider-saved")).to_contain_text("key stored")
    expect(page.locator("#provider-key")).to_have_value("")
    page.locator("#ai-provider").select_option("none")
    page.locator("#provider-save").click()
    expect(page.locator("#provider-saved")).to_contain_text("No AI provider")
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.set_viewport_size({"width": 1440, "height": 1100})
    assert page.evaluate("localStorage.length + sessionStorage.length") == 0


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
    parser.add_argument("--admin-setup", action="store_true", help="Exercise first-run administrator setup and account sign-in")
    args = parser.parse_args()
    with (
        tempfile.TemporaryDirectory(prefix="bantis-audit-browser-") as audit_dir,
        tempfile.TemporaryDirectory(prefix="bantis-response-browser-") as response_dir,
        tempfile.TemporaryDirectory(prefix="bantis-admin-browser-") as admin_dir,
        tempfile.TemporaryDirectory(prefix="bantis-provider-browser-") as provider_fixture_dir,
        ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler) as upstream,
    ):
        audit_path = Path(audit_dir) / "reviews.sqlite3"
        for sequence in range(1, 24):
            append_audit(audit_path, sequence)
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
            "DASHBOARD_STATE_DIR": admin_dir if args.admin_setup else "",
            "DASHBOARD_ORIGIN": origin,
            "DETECTION_ENGINE_URL": f"http://127.0.0.1:{upstream.server_port}",
            "DASHBOARD_POLL_SECONDS": "1",
            "DASHBOARD_AUDIT_PATH": str(audit_path),
            "COPILOT_API_URL": f"http://127.0.0.1:{upstream.server_port}",
            "COPILOT_API_TOKEN": "browser-fixture-copilot-token",
        }
        seed_response_queue(args.python, Path(response_dir), environment)
        factory = "bantis_dashboard.main:create_app"
        if args.admin_setup:
            # Inject a provider transport only in this disposable test factory.
            # Production still uses the fixed HTTPS Anthropic endpoint.
            fixture = Path(provider_fixture_dir) / "provider_browser_fixture.py"
            fixture.write_text('''import httpx
from bantis_dashboard.main import create_app as dashboard_app

def handle(request):
    if request.headers.get("x-api-key") != "browser-fixture-provider-key":
        return httpx.Response(401, json={"error": "private-provider-error"})
    return httpx.Response(200, json={"type": "message", "role": "assistant", "content": [{"type": "text", "text": "OK"}]})

def create_app():
    return dashboard_app(provider_transport=httpx.MockTransport(handle))
''')
            environment["PYTHONPATH"] = provider_fixture_dir + os.pathsep + str(ROOT / "dashboard")
            factory = "provider_browser_fixture:create_app"
        process = subprocess.Popen(
            [
                args.python,
                "-m",
                "uvicorn",
                factory,
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
                if args.admin_setup:
                    check_admin_setup(page, origin, token, args.screenshots)
                else:
                    page.get_by_label("Dashboard access token").fill("wrong")
                    page.get_by_role("button", name="Open dashboard").click()
                    expect(page.locator("#login-error")).to_contain_text("Invalid dashboard access token")
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
                check_incidents(page, args.screenshots)
                check_live_feed(page, args.screenshots)
                check_audit_log(page, audit_path, args.screenshots)
                page.get_by_role("button", name="Sign out").click()
                expect(page.locator("#audit-rows tr")).to_have_count(0)
                expect(page.locator("#login-screen")).to_be_visible()
                expect(page.locator("#incident-rows tr")).to_have_count(0)
                expect(page.locator("#live-rows tr")).to_have_count(0)
                if args.admin_setup:
                    expect(page.locator("#admin-fields")).to_be_visible()
                    expect(page.locator("#admin-password")).to_have_value("")
                    expect(page.locator("#setup-screen")).to_be_hidden()
                assert not errors, errors
                browser.close()
                print(
                    f"PASS: {'administrator wizard and sign-in, ' if args.admin_setup else ''}dashboard, Response review (Approve/Modify/Dismiss), Audit log, Incidents analysis and follow-ups, and Live feed, arrivals, filters, pause/resume, clear, bounded history, gaps, stale data, reconnect, desktop/mobile, text rendering, and logout"
                )
        finally:
            process.terminate()
            process.wait(timeout=5)
            upstream.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()