# Dashboard Foundation

A separate FastAPI service serves the initial dashboard and its local HTML,
CSS, and JavaScript assets. The browser reads incidents through an authenticated
backend and receives periodic status snapshots over WebSocket. No frontend
build, CDN, external font, database, or model key is required.

This is the initial implementation of the
[design baseline](../docs/wizard-dashboard-design.md). Final visual approval
still requires the agreed diagrams. The wizard, Copilot analysis retrieval,
controller review, audit, emergency stop, and resume are not implemented here.
The dashboard does not change controller configuration or execute actions.

## Run locally

Use Python 3.12 or later. From the repository root:

```bash
python3 -m venv dashboard/.venv
dashboard/.venv/bin/python -m pip install -r dashboard/requirements.txt
```

Start the Detection Engine separately following its
[guide](../detection-engine/README.md#running-it), normally on port 8000. Then
choose a unique dashboard access token of at least 32 bytes, enter it through a
hidden shell prompt, and start the dashboard. The following works in Bash and
Zsh and keeps the token out of shell history:

```bash
cd dashboard
printf 'Dashboard access token (at least 32 bytes): '
read -r -s DASHBOARD_TOKEN
printf '\n'
export DASHBOARD_TOKEN
export DASHBOARD_ORIGIN=http://127.0.0.1:8200
export DETECTION_ENGINE_URL=http://127.0.0.1:8000
.venv/bin/python -m uvicorn bantis_dashboard.main:create_app --factory --host 127.0.0.1 --port 8200 --workers 1
```

Open **http://127.0.0.1:8200** and enter the same token. The hostname and port
must match `DASHBOARD_ORIGIN`; `localhost` and `127.0.0.1` are different origins.
Without the Detection Engine, sign-in and the shell still work, and the UI
reports the source as unavailable. No demo incidents are generated.

| Setting | Default | Meaning |
|---|---|---|
| `DASHBOARD_TOKEN` | Required | Separate dashboard credential, 32–512 bytes; never use a controller approver secret. |
| `DASHBOARD_ORIGIN` | `http://127.0.0.1:8200` | Exact browser origin, without a path, query, or credentials. Used for host and browser origin checks. |
| `DETECTION_ENGINE_URL` | `http://127.0.0.1:8000` | Server-side upstream address; never supplied by browser requests. |
| `DASHBOARD_POLL_SECONDS` | `5` | Shared status polling interval, from 1 to 300 seconds. |

Keep this foundation bound to loopback. The Detection Engine still has
unauthenticated routes; a dashboard session does not authenticate event
producers or close the controller's deployment gates. Remote deployment needs
TLS, ingress authentication and limits, and authenticated upstream services.
HTTPS origins cause the session cookie to use `Secure`.

## API and live updates

| Route | Access | Behavior |
|---|---|---|
| `GET /`, `/static/*` | Public shell | Local assets only; contains no incident records or credentials. |
| `GET /health` | Public | Dashboard process liveness, independent of upstream availability. |
| `POST /api/session` | Dashboard token | Creates an opaque, HttpOnly, SameSite=Strict session cookie. |
| `GET /api/session` | Session | Checks current authentication. |
| `DELETE /api/session` | Current cookie | Revokes the session and clears the cookie; idempotent. |
| `GET /api/status` | Session | Most recent shared status snapshot, initially `connecting`. |
| `GET /api/incidents` | Session | Forwards validated severity, pattern, since, limit, and offset parameters. |
| `GET /api/incidents/{id}` | Session | Read-only incident detail. |
| `GET /api/incidents/{id}/events` | Session | Selected evidence fields ordered by UTC timestamp and event ID. |
| `WS /ws` | Session + exact Origin | Sends the latest status immediately, then a snapshot after every poll. |

All Detection Engine requests use GET. Outages return 503, malformed or oversized
upstream data returns 502, and missing incidents return 404. Upstream error text
is not forwarded. Responses are limited to 2 MB and requests have a three-second
HTTP timeout. Redirects and environment proxy inheritance are disabled.

An example WebSocket message:

```json
{
  "type": "dashboard.snapshot",
  "sequence": 1,
  "observed_at": "2026-11-09T09:00:00+00:00",
  "last_success_at": "2026-11-09T09:00:00+00:00",
  "detection_engine": {
    "status": "available",
    "total_incidents": 12
  }
}
```

One lifespan-managed poller queries a single incident and the environment total,
regardless of socket count. This is a periodic snapshot stream, not an ingestion
subscription or durable event log. Sequence numbers are process-local and reset
on restart. Disconnected clients reconnect with backoff from 1 to 30 seconds,
receive the latest snapshot, and reload the selected incident page. The UI also
reloads the page on each poll, so each active browser adds a list GET per interval.
No history is replayed. Manual refresh works independently of the socket.

During an upstream outage, counts retain their last known value with an
unavailable label and last-success timestamp. The incident list retains its last
successful rows with a stale notice. Initial failure displays no data rather
than a zero incident count. The backend does not cache incident pages for new
requests. Filters and pagination survive opening and closing incident detail.

## Session and rendering boundaries

Sessions expire after eight hours, live only in process memory, and disappear on
restart. Use **one worker**: multiple workers do not share sessions or pollers.
At most 128 active sessions are retained. Repeated sign-in replaces the current
session; sign-out revokes its cookie, and open sockets recheck authorization on
poll updates. The access token is not put in URLs or browser storage. Browser
session mutations reject foreign origins; WebSocket handshakes require an exact
origin match. HTTP clients without an Origin header can use the token login.
This is local access control, not a multi-user identity or administrator system.

The interface inserts incident and evidence text through `textContent`, not
HTML. Evidence includes IDs, times, source, type, and only these details:
`scenario`, `status`, `mitre_technique`, `artifact`, `tool_returncode`, `registry`,
and `image`. Raw messages, tool output, and other details are omitted; this is
field selection, not a guarantee that every selected value is free of secrets.
Responses use no-store caching and a same-origin content security policy.

## Verify

From the repository root, install test dependencies in your prepared environment:

```bash
range/.venv/bin/python -m pip install -r dashboard/tests/requirements.txt
range/.venv/bin/python -m pytest dashboard/tests -q
range/.venv/bin/python -m pytest tests/test_e2e_dashboard.py -q
node --check dashboard/bantis_dashboard/static/app.js
git diff --check
```

The integration test also requires the
[root integration dependencies](../tests/README.md) and permission for loopback
listeners. It seeds a disposable Detection Engine, reads the real query API,
and verifies selected evidence and WebSocket session revocation. No external
APIs, real credentials, commits, or response actions are used.

An optional browser check starts disposable dashboard and fixture services,
verifies desktop and mobile flows, and tears them down. Install Playwright
1.61.0 and its Chromium browser into a separate test environment, then run its
Python interpreter with:

```bash
python dashboard/scripts/browser_smoke.py --python "$PWD/range/.venv/bin/python" --screenshots /tmp/bantis-dashboard-preview
```

The script covers sign-in failure and success, live updates, pagination,
filters, empty results, evidence, untrusted text, stale data, reconnection,
mobile overflow, and sign-out. Screenshots contain synthetic test incidents.
CI runs API/WebSocket tests on Python 3.12 and 3.14, checks JavaScript syntax,
and includes the real query integration in the root end-to-end suite. Browser
checks are optional and are not configured as a CI job.