# Dashboard Foundation

A separate FastAPI service serves the initial dashboard and its local HTML,
CSS, and JavaScript assets. The browser reads incidents through an authenticated
backend and receives periodic status and event snapshots over WebSocket. No frontend
build, CDN, external font, database, or model key is required.

This is the initial implementation of the
[design baseline](../docs/wizard-dashboard-design.md). Final visual approval
still requires the agreed diagrams. The wizard, emergency stop, and resume are not implemented here.
Audit log provides read-only access to the local controller event journal.
The Incidents page includes recorded Copilot analysis and follow-up questions.
Optional response review connects incident proposals to the local controller's
Approve, Modify, and Dismiss flow. Approval can execute actions under the existing
controller configuration.

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
| `COPILOT_API_URL` | `http://127.0.0.1:8100` | Server-side Copilot API address. |
| `COPILOT_API_TOKEN` | Optional | Copilot service bearer token (at least 16 ASCII characters, no whitespace); kept server-side. Without it, the panel reports unconfigured. |
| `DASHBOARD_AUDIT_PATH` | Optional | Server-configured path to the controller `reviews.sqlite3`; absent means unconfigured. The dashboard only reads it. |
| `DASHBOARD_RESPONSE_ENABLED` | `false` | Enable host-local controller review using the dashboard process's controller environment and OS identity. |
| `DASHBOARD_POLL_SECONDS` | `5` | Shared status and event polling interval, from 1 to 300 seconds. |

Keep this foundation bound to loopback. The Detection Engine still has
unauthenticated routes; a dashboard session does not authenticate event
producers or close the controller's deployment gates. Remote deployment needs
TLS, ingress authentication and limits, and authenticated upstream services.
HTTPS origins cause the session cookie to use `Secure`.

## API and live updates

| Route | Access | Behavior |
|---|---|---|
| `GET /`, `/live-feed`, `/incidents`, `/audit-log`, `/static/*` | Public shell | Local assets only; contains no incident records, event records, or credentials. |
| `GET /health` | Public | Dashboard process liveness, independent of upstream availability. |
| `POST /api/session` | Dashboard token | Creates an opaque, HttpOnly, SameSite=Strict session cookie. |
| `GET /api/session` | Session | Checks current authentication. |
| `DELETE /api/session` | Current cookie | Revokes the session and clears the cookie; idempotent. |
| `GET /api/audit-log` | Session | Read-only, verified, filtered controller events with pagination. |
| `GET /api/status` | Session | Most recent shared status snapshot, initially `connecting`. |
| `GET /api/incidents` | Session | Forwards validated severity, pattern, since, limit, and offset parameters. |
| `GET /api/incidents/{id}` | Session | Read-only incident detail. |
| `GET /api/incidents/{id}/events` | Session | Selected evidence fields ordered by UTC timestamp and event ID. |
| `GET /api/incidents/{id}/analysis` | Session | Selected recorded analysis fields from the authenticated Copilot API. |
| `GET /api/incidents/{id}/questions` | Session | Recorded questions and replies in chronological order. |
| `POST /api/incidents/{id}/questions` | Session + same Origin | Validated question; calls the Copilot once, with no automatic retry. |
| `GET /api/incidents/{id}/proposals` | Session | Pending controller proposals for this incident, exact hashes, and execution mode. |
| `POST /api/incidents/{id}/review` | Session + same Origin + operator secret | Approve, Modify, or Dismiss an exact proposal through the controller. |
| `WS /ws` | Session + exact Origin | Sends the latest status immediately, then a snapshot after every poll. |
| `GET /api/live-feed` | Session | Most recent shared event snapshot; preserves the last successful window during outages. |
| `WS /ws/events` | Session + exact Origin | Sends the current event window immediately, then a snapshot after every event poll. |

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

One lifespan-managed status poller queries a single incident and the environment total,
regardless of socket count. A separate shared poller reads the recent event window
for Live feed. These are periodic snapshot streams, not an ingestion
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

## Incidents and AI analysis

Open **http://127.0.0.1:8200/incidents** or select **Incidents**. Severity,
exact pattern, UTC start time, and pagination use the Detection Engine query API.
Opening and closing an investigation preserves the current list state.

Start the [Copilot worker and API](../ai-copilot/README.md) with the same decision
log, then configure `COPILOT_API_URL` and `COPILOT_API_TOKEN` on the dashboard
process and restart it. The dashboard token and Copilot bearer token are separate
credentials. Use hidden shell prompts for both; never put them in URLs or browser
storage. No model key is needed by the dashboard.

The investigation displays incident facts and a selected evidence timeline beside:

- Recorded reasoning, AI confidence (separate from detection confidence), model,
  generation time, decision record identity, outcome, and recommendation.
- Distinct states for successful, skipped, failed, and absent analysis. An absent
  decision does not prove a provider outage or deferral: the worker does not
  persist those transient states. The panel explains this uncertainty.
- Ordered recorded follow-up questions and answers. Sending is enabled only for
  successful analysis with grounding context and after conversation retrieval.
  The Copilot enforces credential screening, rate limits, and its token budget.
- **Refresh analysis** retrieves analysis and conversation without replacing a
  draft. Analysis is loaded on opening and refreshed manually, independently of
  the incident list's periodic updates. Failed refreshes retain previous content
  with a stale notice and disable questions until a successful refresh.

Follow-ups can incur provider cost. Submission is disabled while a request is in
flight. A failed or interrupted request may already have reached the provider;
refresh conversation before retrying. The dashboard never retries POST requests.
GET requests have a three-second timeout; questions have a 90-second timeout.
Copilot responses are limited to 2 MB, validated, and rendered as plain text.
Prompts, raw provider attempts, and request payloads are excluded from retrieval.
Service errors are sanitized, including invalid bearer-token responses, which do
not revoke the independent dashboard session. Evidence still works if Copilot is
unconfigured or unavailable. Recommendations and answers execute no actions;
response operations use the separate Response review panel or local controller CLI.

## Response review

Run the dashboard and controller on the same host, with the repository's
`response-controller/` directory available beside `dashboard/`. The dashboard
Python interpreter must have the controller dependencies installed:

```bash
range/.venv/bin/python -m pip install -r response-controller/requirements.txt
```

Configure the dashboard process with the same `BANTIS_STATE_DIR`,
`RESPONSE_ENABLED_ACTIONS`, `RESPONSE_DRY_RUN`, and scoped executor settings used
by the controller CLI. Set `RESPONSE_APPROVER_SECRET_FILE` to the existing private,
operator-owned approval secret file, then set `DASHBOARD_RESPONSE_ENABLED=true`
and restart the dashboard. The existing review journal must already exist;
queue proposals through controller policy synchronization or `cli.py propose`.
No proposals are created from Copilot recommendations or answers. Set
`DASHBOARD_AUDIT_PATH` to the same journal to inspect review records in Audit log.

Open an incident and scroll to **Response review**. The panel shows pending
proposal IDs, full hashes, parameters, policy rules, expiry, required reviewers,
and dry-run/live mode. Enter the separate operator secret for each decision.
**Approve** calls the existing executor, including enablement, expiry, distinct
reviewer, kill-switch, dry-run, precondition, and verification checks. The result
reports the controller status and reasons; a refused, failed, or invalidated
action is never labeled successful. **Modify** requires replacement parameters
as a JSON object and a reason, closes the original proposal, and queues a new
proposal requiring fresh approval. **Dismiss** requires a reason and closes the
proposal without execution. Current hold and lift actions accept only `{}`.

The bridge invokes a fixed local Python entry point without a shell. Secrets
travel in the request body and process stdin, never command-line arguments or
audit fields, and the password field clears on submission. Browser-supplied
actor names, controller paths, action types, and execution-mode changes are
rejected. All browser sessions use the dashboard host's OS identity; additional
sessions cannot satisfy a two-person requirement. A second distinct operator
must use their own OS identity and private secret through the CLI.

Submissions disable all decision controls and are never retried automatically.
Successful decisions refresh the queue. On error, manually refresh proposals and
the audit log before retrying: an interrupted or timed-out request may already
have recorded a decision or started execution. The bridge timeout is 120 seconds.
Review supports up to 100 pending proposals per incident and 16 KB per request;
larger queues require the CLI. Unconfigured review and missing or corrupt state
produce explicit errors. This optional bridge needs write access to controller
state and uses the controller's journal initialization/migration checks; the
separate Audit log endpoint remains read-only.

## Audit log

Set `DASHBOARD_AUDIT_PATH` to the absolute path of the existing controller journal
(the file is `$BANTIS_STATE_DIR/reviews.sqlite3`) in the dashboard process, restart
it, and open **http://127.0.0.1:8200/audit-log**. For example, when the dashboard
runs on the same host and `BANTIS_STATE_DIR` already identifies controller state:

```bash
export DASHBOARD_AUDIT_PATH="$BANTIS_STATE_DIR/reviews.sqlite3"
```

The dashboard account needs read access to the journal and its parent directory;
use a read-only mount for a separate container, including SQLite WAL sidecars
when the controller uses WAL. Do not make the state directory publicly readable.
The Audit log reader never initializes, migrates, repairs, or appends to the database,
and has no browser parameter for changing the source path. The controller does
not need a new HTTP listener. Detection Engine and Copilot outages do not prevent
audit reads. Unconfigured, missing, unreadable, or unsupported journals return an
explicit unavailable state, distinct from an empty valid journal.

- Entries are ordered by descending journal sequence, independent of event time.
  Filters match exact event, actor (including `initiated_by`), action ID, incident
  ID, and outcome. Inclusive UTC start/end times filter recorded event times.
  Pages contain 20, 50, or 100 entries, with the total matching count.
- Each successful read verifies **every event**, including those outside the
  filters, in one read transaction. The page shows the checked journal head and
  observation time. Interior deletion, changed payloads, and broken hashes fail
  the read; no partial result is returned. **Consistent** means local event-chain
  consistency, not external anchoring or proof of authenticity. Valid tail
  deletion, journal replacement, and administrator rebuilding require an
  independently retained checkpoint to detect. Proposal and approval tables are
  not covered by this event-chain check.
- Pagination retains `through_sequence` so new appends do not shift the current
  browsing window. **Refresh log** starts from the latest sequence and first
  page, keeping filters. Filter changes also start a fresh browsing snapshot.
  Reads are manual; there is no audit WebSocket or periodic polling.
- Open an event for its identities, UTC time, outcome, proposal/entry hashes,
  attempt ID, and selected details: reason(s), verification flag, stop level,
  AI-off flag, replacement/rollback links, policy rule, and hourly bound. Full
  proposals, parameters, AI context, provider attempts, plans, and rollback state
  are omitted. Selected text is not secret detection; restrict access to the
  journal and dashboard. Free-text detail fields are bounded in the projection.
- Loading, empty results, and failures have separate messages. A failed refresh
  keeps previous rows with a stale timestamp and marks current integrity as
  **Not confirmed**. Pagination is disabled until a successful read. Sign-out
  clears audit rows and event details.

The endpoint accepts `limit` (1–100), `offset` (0–100,000), `through_sequence`,
`actor`, `action_id`, `incident_id`, `event`, `status`, `since`, and `until`.
Server reads are bounded to 100,000 events, 64 MB of stored payloads, 1 MB per
payload, and a three-second processing budget (SQLite lock waits are capped at
one second). Larger journals should be inspected through the controller CLI.
Older schemas are never migrated by the dashboard; upgrade with the controller.

## Live feed

Restart both services after updating, then open
**http://127.0.0.1:8200/live-feed** or select **Live feed** in the navigation.
It includes uncorrelated events such as ordinary `http_request` records, not
just incidents. There is no synthetic traffic in the running application.

- The Detection Engine's `GET /events?limit=500` returns `{total, limit, items}`.
  Receipt time and event ID determine newest-first ordering; an event with an
  old occurrence time still appears when it is newly ingested.
- The server polls at `DASHBOARD_POLL_SECONDS` (5 seconds by default). Event
  snapshots are shared across clients; opening another socket adds no upstream
  event query. This is periodic streaming of a recent window, not a durable
  delivery or replay protocol.
- The current window holds at most 500 events. Filters for log level, exact
  source, exact event type, and case-insensitive text search apply locally to
  this window. Search covers IDs, source, type, logger, and selected details.
- **Pause display** freezes the visible rows while background snapshots continue.
  A pending count identifies new IDs in the current window. **Resume display**
  shows the latest window. **Clear view** hides currently known IDs only in this
  page; they do not reappear on the next poll, and no stored events are deleted.
  Navigation or reload resets pause, clear, and filter state.
- Click an event to inspect its ID, level, logger, source, occurrence time,
  receipt time, and selected scalar details. Raw messages and tool output are
  omitted at both the query and dashboard boundaries. This is field selection,
  not secret detection or a guarantee about the contents of selected fields.
- Unavailable sources preserve the last successful rows with a stale notice.
  A source that has never succeeded shows unavailable with no data, not zero.
  Session expiry and sign-out also revoke the event stream; cleared browser
  state does not retain event rows after sign-out.
- Snapshots contain `type: "events.snapshot"`, process-local `sequence`,
  `status`, `observed_at`, `last_success_at`, `poll_seconds`, `total`, `limit`,
  `items`, and `gap_possible`. Missing overlap, a count reset, or arrivals beyond
  the window flag possible gaps. A browser that misses more than a window while
  paused or disconnected also displays a gap warning. This warning is
  conservative; continuous coverage is not guaranteed and older events are not
  replayed. The database still stores them.

**Refresh feed** retrieves the current cached snapshot even if the WebSocket is
disconnected. It does not create a per-client source poll. Invalid or oversized
upstream event responses mark the source unavailable and preserve the old window.

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
and verifies selected evidence, uncorrelated event arrivals, duplicate ingestion,
old event timestamps, and WebSocket session revocation. No external
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
mobile overflow, and sign-out. Live feed checks also cover arrivals, filters,
pause/resume, clear, bounded history, and gaps. Incidents checks cover recorded
analysis, questions, stale analysis, absent/skipped/failed states, preserved drafts,
and mobile investigation layout. Response review uses a separate disposable
controller journal and checks wrong secrets, invalid JSON, replacement proposals,
dismissal, approval blocked by the kill switch, and secret-field clearing.
Audit checks use a disposable journal and cover
filters, stable pagination during appends, event details, integrity failure,
unavailability, empty history, mobile layout, and sign-out. Screenshots contain
synthetic test incidents, events, and audit entries.
CI runs API/WebSocket tests on Python 3.12 and 3.14, checks JavaScript syntax,
and includes Detection Engine tests and real query integration in the end-to-end job. Browser
checks are optional and are not configured as a CI job.