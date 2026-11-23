# Dashboard Foundation

A separate FastAPI service serves the initial dashboard and its local HTML,
CSS, and JavaScript assets. The browser reads incidents through an authenticated
backend and receives periodic status and event snapshots over WebSocket. No frontend
build, CDN, external font, or model key is required. Token-only mode needs no
database; optional administrator setup uses a private local SQLite database.

This is the initial implementation of the
[design baseline](../docs/wizard-dashboard-design.md). Final visual approval
still requires the agreed diagrams. The wizard supports administrator creation
dashboard capability permissions, encrypted local secret storage, and optional
AI provider and Telegram steps with real connection tests. The service startup
step orchestrates Docker Compose and streams live operational logs. Browser
service-address configuration, emergency stop, and resume remain open.
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
| `DASHBOARD_TOKEN` | Required | Dashboard credential in token-only mode; setup bootstrap token in administrator mode. 32–512 bytes; never use a controller approver secret. |
| `DASHBOARD_STATE_DIR` | Optional | Absolute path to a private, operator-owned directory. Enables first-run administrator creation and account sign-in. Without it, token-only mode remains available. |
| `BANTIS_SECRETS_KEY_FILE` | `$DASHBOARD_STATE_DIR/.secrets.key` | Optional absolute path to an existing private Fernet key. Set the same path in Copilot. An explicitly configured missing key is never generated. |
| `DASHBOARD_ORIGIN` | `http://127.0.0.1:8200` | Exact browser origin, without a path, query, or credentials. Used for host and browser origin checks. |
| `DETECTION_ENGINE_URL` | `http://127.0.0.1:8000` | Server-side upstream address; never supplied by browser requests. |
| `COPILOT_API_URL` | `http://127.0.0.1:8100` | Server-side Copilot API address. |
| `COPILOT_API_TOKEN` | Optional | Copilot service bearer token (at least 16 ASCII characters, no whitespace); kept server-side. Without it, the panel reports unconfigured in manual mode. Managed orchestration supplies an encrypted service token automatically. |
| `DASHBOARD_AUDIT_PATH` | Optional | Server-configured path to the controller `reviews.sqlite3`; absent means unconfigured. The dashboard only reads it. |
| `DASHBOARD_RESPONSE_ENABLED` | `false` | Enable host-local controller review using the dashboard process's controller environment and OS identity. |
| `DASHBOARD_ORCHESTRATION_ENABLED` | `false` | Allow administrator-authorized startup of the fixed local Compose stack; requires administrator mode and host Docker access. |
| `DASHBOARD_ORCHESTRATION_RANGE` | `true` | Include Range API, PostgreSQL, Redis, and Nginx. Set false to manage platform services only. |
| `DASHBOARD_RANGE_PORT` | `8080` | Loopback port for the managed Range Nginx service. |
| `DASHBOARD_POLL_SECONDS` | `5` | Shared status and event polling interval, from 1 to 300 seconds. |

Keep this foundation bound to loopback. The Detection Engine still has
unauthenticated routes; a dashboard session does not authenticate event
producers or close the controller's deployment gates. Remote deployment needs
TLS, ingress authentication and limits, and authenticated upstream services.
HTTPS origins cause the session cookie to use `Secure`.

## Administrator setup

To enable the administrator step, set a persistent state directory in the
dashboard process before starting it:

```bash
export DASHBOARD_STATE_DIR="$HOME/.local/state/bantis-dashboard"
```

Keep `DASHBOARD_TOKEN` configured through the hidden prompt shown above. In
administrator mode it authorizes **only initial account creation**. Open
`http://127.0.0.1:8200/setup` or any dashboard page. Before an account exists,
the wizard asks for the bootstrap token, an administrator username, a password,
and password confirmation. Usernames contain 3–64 letters, digits, dots,
underscores, or hyphens, start with a letter or digit, and are case-insensitive.
Passwords must match, contain 15–128 characters, and must not be blank. Spaces
and Unicode are allowed in passwords; passwords are never trimmed or truncated.

Creation finishes this wizard step and opens administrator sign-in. Sign in
with the new username and password to access the existing dashboard. This does
not report completion of the remaining wizard steps: connections and response
configuration still use host settings. Open **Setup** after signing in to select
permissions, then select an AI provider and configure or skip Telegram. Administrator login never supplies the
separate controller approval secret or changes execution mode.

Account state persists in `$DASHBOARD_STATE_DIR/admin.sqlite3`. A singleton
database constraint and write transaction prevent concurrent requests, retries,
reloads, or a second setup session from replacing the established account.
After creation, `/setup` shows sign-in. Token login cannot open the dashboard
at any point in administrator mode. Restarting retains the account and setup
lock, while existing browser sessions expire on restart as before.

The directory is created with mode `0700` and the database with `0600`; existing
paths must be private and owned by the dashboard OS user. Provision a persistent
volume when using containers and restrict backups. Passwords use a random salt
and versioned scrypt hashing (`N=2^17`, `r=8`, `p=1`), following the
[OWASP scrypt baseline](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt).
Plaintext passwords, confirmation values, and bootstrap tokens are never stored
in account records or returned in API responses. Creation and sign-in clear
submitted secret fields; no credentials are written to browser storage.

Setup and administrator sign-in require an exact `Origin` header. They share a
limit of 10 authentication attempts per rolling minute across clients in the
single worker. Password hashing is limited to one operation at a time and needs
approximately 128 MiB of working memory; busy requests return 429. The rate
limit is process-local and resets on restart. Keep the existing loopback/TLS and
ingress boundaries; this is one administrator for one environment, not a user
management or password-recovery service.

Failures preserve the username and clear submitted secrets. Creation is never
automatically retried. Use **Check setup status** after interrupted delivery: a
completed creation switches to sign-in; an incomplete transaction can be retried.
Missing or corrupt state during runtime returns unavailable and does not create
a replacement database. Invalid state or permissions at startup prevent startup.
There is no browser account-reset or password-recovery endpoint. Back up the
private state and investigate storage failures on the host; do not delete an
established account database to resolve an ordinary sign-in error.

## Permissions and encrypted storage

Sign in as administrator and open **Setup** (`http://127.0.0.1:8200/setup`).
The first screen is **Choose dashboard permissions**. Save the defaults for
read-only dashboard access, or explicitly enable individual capabilities:

| Permission | Scope |
|---|---|
| Allow dashboard AI requests | Provider connection tests, saving tested provider credentials, and new follow-up questions through this dashboard. Recorded analysis and history remain readable. The separate Copilot worker keeps its host configuration. |
| Allow Telegram test messages | The optional Telegram setup test and saving tested bot credentials. Skipping Telegram is always available. |
| Allow manual response decisions | Dashboard Approve, Modify, and Dismiss requests. The host must also enable `DASHBOARD_RESPONSE_ENABLED`; the separate controller secret and all existing controller policy still apply. |

All three permissions default to off in administrator mode, including after an
upgrade with existing integration settings. Saving permissions takes effect on
subsequent dashboard requests, clears earlier provider/Telegram test receipts,
and rejects test results arriving after a permission change. An already sent
remote request or controller operation may still finish. These controls never
write controller action allowlists, dry-run settings, automatic execution flags,
or kill-switch state. Token-only deployments retain their existing host-configured
behavior and cannot use this administrator-only step.

The screen reports whether encrypted storage and private file permissions are
ready. Choose **Save permissions**, then **Next: AI provider**. Use **Back to
permissions** to revise choices. Reloading starts at Permissions with saved
choices restored. Errors keep the screen available for checking storage and
retrying; a storage failure cannot silently grant a capability.

Wizard configuration uses [Fernet authenticated encryption](https://cryptography.io/en/latest/fernet/)
through `cryptography`: AES-128-CBC with HMAC-SHA256. `ai-provider.json`,
`telegram.json`, and `permissions.json` contain version-2 ciphertext envelopes.
The encrypted payload includes a document purpose, so copying provider ciphertext
into a permissions or Telegram file fails validation. Decrypted values stay in
server memory and are never returned as secrets to the browser. Administrator
passwords remain salted scrypt hashes, separate from reversible integration
credentials. Environment-only bootstrap, service, and controller secrets are
not copied into this store.

The dashboard generates a random key at `$DASHBOARD_STATE_DIR/.secrets.key` on
first use. It publishes the complete key atomically without overwriting an
existing key, writes key/configuration files as `0600`, and requires private
operator-owned `0700` directories. Reads reject symlinks, non-regular files,
oversized documents, public files, invalid ciphertext, and wrong keys. Saves
use a temporary encrypted file, file sync, atomic replacement, and directory
sync. Failures before replacement preserve the previous file; refresh after
uncertain delivery before retrying.

Keep the key private and back it up separately from encrypted configuration.
For a separately provisioned key, set `BANTIS_SECRETS_KEY_FILE` to its absolute
path in both dashboard and Copilot processes. The file must contain a Fernet key
(a URL-safe base64-encoded 32-byte random key), be owned by the service user, and
have mode `0600` inside a private directory. An explicitly configured key must
already exist. Do not replace the key to fix a startup error: there is no browser
reset or automatic key regeneration when encrypted files exist. Restore the
original key and correct permissions. Key rotation requires an explicit offline
migration and is not provided by this step.

At startup the dashboard validates and migrates earlier private version-1
provider and Telegram files to encryption, preserving the filenames and
selection. Migration is atomic per file, creates no plaintext backup, and can
resume after interruption with the same key. Invalid or public legacy files
stop startup rather than being silently rewritten. Historical backups and disk
remnants are not erased by migration. Start the updated dashboard before
restarting Copilot so it can migrate old provider settings. Copilot requires
the encrypted format and original key when `BANTIS_AI_CONFIG` is set; it never
falls back to an environment key after decryption failure.

Encryption protects ciphertext without its key. A user or process that can read
both the key and configuration can recover secrets; it does not protect against
a compromised service account or host. Keep state outside the repository and
continue to restrict the dashboard to loopback or authenticated TLS ingress.

### Run and inspect this step

From the repository root, update the dashboard dependencies:

```bash
dashboard/.venv/bin/python -m pip install -r dashboard/requirements.txt
export DASHBOARD_STATE_DIR="$HOME/.local/state/bantis-dashboard"
export DASHBOARD_ORIGIN=http://127.0.0.1:8200
printf 'Dashboard bootstrap token (32–512 bytes): '
read -r -s DASHBOARD_TOKEN
printf '\n'
export DASHBOARD_TOKEN
cd dashboard
.venv/bin/python -m uvicorn bantis_dashboard.main:create_app --factory --host 127.0.0.1 --port 8200 --workers 1
```

Create the administrator if prompted, sign in, and open **Setup → Permissions**.
The screen works while the Detection Engine is offline. For incident data, start
the [Detection Engine](../detection-engine/README.md#running-it) on port 8000;
Copilot remains optional. Use the same persistent state directory after restart.

## AI provider setup

With administrator mode enabled, open **Setup** (`/setup`), enable dashboard AI
requests in Permissions, save, and choose **Next: AI provider**. Select
**Claude (Anthropic)**, enter a model ID available to your account and an API key,
then choose **Test connection**. Claude is the implemented v1 provider; OpenAI
and local providers are not advertised as available.

The backend makes one real HTTPS request to Anthropic's
[Messages API](https://platform.claude.com/docs/en/api/messages/create), using
the entered key and model, the fixed text `Reply with OK.`, and a 16-token output
limit. No incident data, questions, or controller state are sent. A successful
test requires a valid assistant message with nonempty text. Invalid credentials,
model access problems, rate limits, outages, malformed responses, and timeouts
have distinct sanitized errors. A timeout may already have incurred usage;
tests are never retried automatically. Tests have their own process-local limit
of 10 per rolling minute and are outside the Copilot's incident token budget.

Only a successful test enables **Save provider**. The server binds the tested
key and model to this session through a receipt valid for five minutes. Editing
the selection or model requires a new test; the save API cannot substitute
different credentials. Secret fields clear on submission. Pending keys are
discarded after save, logout, session rotation, restart, or expiry cleanup
(every 30 seconds). Expired or foreign-session receipts cannot be saved.

Saving atomically writes `$DASHBOARD_STATE_DIR/ai-provider.json` with mode `0600`
in the existing private directory. The file encrypts the API key and model using
the local storage key; protect the key and back it up separately. Retrieval
returns only provider, model, and whether a key is stored. No key is returned to
the browser or written to browser storage. Select **No AI provider** and save
to remove the stored key and continue without AI; no connection request occurs.

In both Copilot worker and API processes, configure the same absolute file path
before starting or restarting them:

```bash
export BANTIS_AI_CONFIG="$DASHBOARD_STATE_DIR/ai-provider.json"
```

Set `DASHBOARD_STATE_DIR` to the same absolute location in that shell, or specify
the complete file path directly. The Copilot loads this file at startup; saving
does not reconfigure an already running process. The file takes precedence over
`ANTHROPIC_API_KEY`. Explicit **No AI provider**, missing files, and invalid or
publicly readable files make AI unavailable without falling back to another key.
When `BANTIS_AI_CONFIG` is unset, existing environment-based configuration still
works. Manual deployments still configure Copilot API connectivity and the
separate `COPILOT_API_TOKEN`; managed orchestration supplies the service
credential automatically. This step does not start services or mark the
entire wizard complete.

## Optional Telegram setup

In administrator mode, open **Setup**, save Permissions, then choose **Next:
AI provider** followed by **Next: optional Telegram** after
the AI provider step. Choose **Skip Telegram** and **Skip Telegram and continue**
to save an explicit disabled selection without a token or network request. This
also removes any previously stored bot token. Detection and the dashboard work
without Telegram. **Back to AI provider** preserves the chat ID during navigation.

To configure Telegram, first allow Telegram test messages in Permissions. Create a bot using Telegram's BotFather. Start a private
chat with it, or add it to the target group or channel and allow it to send
messages. Enter its bot token and a numeric chat ID (preserve the minus sign for
groups), or a public channel username such as `@my_channel`. Choose **Send test
message**. The server sends one fixed English setup message using Telegram's
[sendMessage API](https://core.telegram.org/bots/api#sendmessage). No incident,
account, or controller data is sent. Success requires a valid sent-message
response, including the expected numeric chat ID when one was entered.

A successful test enables **Save Telegram** for five minutes using a receipt
bound to the tested token, chat, and administrator session. Editing the inputs
requires a new test. Tests have a separate limit of 10 per rolling minute and
are never automatically retried. A timeout can occur after delivery; check the
chat before manually retrying. Invalid tokens, inaccessible chats, rate limits,
malformed replies, and outages show sanitized English errors and cannot save an
enabled configuration. Failures before atomic replacement preserve the previous file; refresh saved
configuration after interrupted delivery before retrying.

Saving atomically writes `$DASHBOARD_STATE_DIR/telegram.json` with mode `0600`
inside the existing private directory. The version-2 envelope encrypts the
selection and credentials. Its decrypted payload contains `version: 1`,
`enabled: true`, `bot_token`, and `chat_id`; a skipped payload contains only
`version: 1` and `enabled: false`. Protect the original encryption key and
back it up separately from this file. Retrieval returns only configured and
enabled flags, the chat ID, and whether a token exists. The token field clears
on test submission and logout, and credentials never enter browser storage.
HTTPX request logs redact the token required in Telegram's upstream API path.
Receipts clear on save, logout, session rotation, restart, and expiry cleanup.
Saved selections survive restart; unreadable, malformed, or public files report
unavailable rather than silently disabling Telegram.

After saving either selection, choose **Next: start services**. This implements
connection setup and its test message only; automatic incident notification
delivery remains future work. Saving does not mark the entire wizard complete,
change controller permissions, or enable response actions.

## Service orchestration and live logs

The final implemented setup step starts the configured services through the
repository's root [Compose definition](../compose.yaml). The dashboard runs on
the host as the coordinator. Containers never receive the Docker socket.

| Service | Startup behavior |
|---|---|
| Detection Engine | Required; starts first with persistent SQLite data and an HTTP health check. |
| Copilot API | Required for recorded analysis/history; starts with encrypted provider settings and a managed API credential. Works with an explicit No AI choice. |
| Copilot worker | Starts when dashboard AI requests are allowed and a Claude key is saved. Otherwise clearly marked unselected. A running worker has no separate health endpoint. |
| Range API, PostgreSQL, Redis, Nginx | Included by default. Dependencies wait for health checks. Set `DASHBOARD_ORCHESTRATION_RANGE=false` for platform services only. |
| Response Controller | Remains the existing host-local bridge/CLI, governed by its separate permissions and policy. No executable response actions are enabled by startup. |
| Attack simulations | Run separately through the existing CLI; starting services does not launch attacks. |

### Run the complete setup flow

Use a Linux host with an accessible local Docker daemon and Docker Compose v2
supporting `up --wait`. The dashboard OS account must already have Docker access.
This is a privileged host capability: enable it only for the trusted local
administrator. The host flag is off by default; administrator sign-in and an
exact dashboard Origin are required to start services.

For Range, prepare the existing host configuration once. Copy
`range/.env.example` to `range/.env` only if the file does not already exist.
Replace the database, Redis, and JWT placeholders; keep connection URLs in sync
with their passwords. Set mode `0600` on the file. These remain existing Range
environment settings and are not imported into the wizard secret store.
To omit Range, set `DASHBOARD_ORCHESTRATION_RANGE=false` instead.

From the repository root:

```bash
python3 -m venv dashboard/.venv
dashboard/.venv/bin/python -m pip install -r dashboard/requirements.txt
export DASHBOARD_STATE_DIR="$HOME/.local/state/bantis-dashboard"
export DASHBOARD_ORIGIN=http://127.0.0.1:8200
export DASHBOARD_ORCHESTRATION_ENABLED=true
printf 'Dashboard bootstrap token (32–512 bytes): '
read -r -s DASHBOARD_TOKEN
printf '\n'
export DASHBOARD_TOKEN
cd dashboard
.venv/bin/python -m uvicorn bantis_dashboard.main:create_app --factory --host 127.0.0.1 --port 8200 --workers 1
```

Open **http://127.0.0.1:8200/setup**, create the administrator if necessary, and
sign in. Save **Permissions**, select and save an **AI provider** or **No AI
provider**, then configure or **Skip Telegram**. Choose **Next: start services**
and **Start all configured services**. No separate manual service launch is
needed. Image builds/downloads may take several minutes on first use.

The page shows selected services, current container/health states, startup
progress, and live service output. A successful start requires all selected
HTTP/database/cache services to report healthy and the optional worker to be
running. Compose's [dependency ordering](https://docs.docker.com/compose/how-tos/startup-order/)
and [`up --wait`](https://docs.docker.com/reference/cli/docker/compose/up/) drive
startup; container existence alone cannot mark this step ready. Health checks
establish service availability, not authentication completeness or deployment
security. The dashboard link appears only after a fresh successful status check.

The host endpoints default to Detection Engine **127.0.0.1:8000**, Copilot API
**127.0.0.1:8100**, and Range **127.0.0.1:8080**. Database and Redis ports remain
internal. `DETECTION_ENGINE_URL` and `COPILOT_API_URL` may select other local HTTP
ports; managed URLs must use `localhost` or `127.0.0.1` without a path.
`DASHBOARD_RANGE_PORT` changes the managed Range port. These managed port choices
take precedence over the standalone Range's `NGINX_PORT`. Resolve conflicts
with manually started services before retrying; orchestration never stops
unrelated containers or host processes.

### State, credentials, and retries

The private state directory contains persistent `detection-data/` and
`copilot-data/` directories. Range PostgreSQL uses a Compose project volume.
The project name derives from the absolute state directory and appears in the
status response. Keep that path stable across restarts; using a different path
creates a separate project and Range volume. This does not adopt or overwrite
the standalone `bantis-range` deployment.

The dashboard generates a separate Copilot API token and saves it only in the
encrypted `orchestration.json` document. In managed mode this credential replaces
the manually supplied `COPILOT_API_TOKEN` for the managed API connection.
Copilot reads it through `BANTIS_COPILOT_TOKEN_CONFIG`, decrypting the mounted
file at startup. The token is absent from command arguments, Docker environment
metadata, logs, and browser responses. Invalid encrypted credential files stop
API startup without falling back to another token.

Copilot receives read-only mounts of the private dashboard state and key
directory under the same trusted OS identity. With an external encryption key,
use a dedicated private key directory containing only this deployment's key.
Keep the original key and state available at their configured paths. Container
access to these mounts belongs to the same trusted service boundary as the
host-local Copilot configuration.

The Detection Engine also receives those state and key mounts read-only so it
can decrypt the saved Telegram and permissions documents in memory. It sends
plain-text Telegram alerts only for `critical` incidents and only while
**Allow Telegram messages** is enabled. The critical-alert outbox is committed
with each incident; Telegram delivery failures remain queued and are retried
on later correlation passes. High-severity incidents are still available in
the dashboard and incident API but do not generate Telegram messages.

Duplicate starts share the active task, and an already ready stack is not
started again. A private process lock allows one coordinator per state directory;
run one dashboard worker. Startup failures and timeouts retain containers and
data for diagnosis. Correct the issue, refresh status, and retry explicitly.
There is no automatic retry of a failed startup and no browser volume-reset or
stack-deletion operation. Failed status refreshes preserve the last known data
with stale/error notices. A dashboard restart discovers existing containers
without rerunning startup. Closing the dashboard stops its CLI watchers, not
the managed containers; container restart policies remain in effect.

Saving new provider credentials does not restart an already running Copilot.
After changing credentials, restart the managed Copilot services from the host
using the displayed project name, then refresh the startup screen. Dashboard
permissions control dashboard requests; revoking AI access does not terminate
an already running worker or cancel an in-flight remote request. Controller
execution settings and stop state remain independently governed.

### Live log behavior

Logs stream through session-protected `/ws/setup/services` with exact Origin
checks and periodic session revalidation. Logout clears the browser view and
revokes the stream. WebSocket reconnects and status refreshes do not launch
services again. The page supports startup/service filters, pause/resume, and
clearing the local view. Log content renders as text, including HTML-like data.

The dashboard keeps at most 500 redacted lines in memory, with bounded line
lengths; it omits oversized lines and reports history gaps after overflow or
restart. The browser suppresses duplicate/stale updates, reconnects after
interruptions, and marks old service checks stale. Known configured credentials,
URL credentials, common token/password fields, and private key blocks are
redacted before entering the retained buffer. This is not an audit log or a
guarantee that every application value is non-sensitive. Raw Docker logs remain
on the host, with size/count rotation configured by Compose. Keep operational
log access limited to the trusted administrator.

### Verify orchestration

From the repository root:

```bash
range/.venv/bin/python -m pytest dashboard/tests -q
python3 dashboard/scripts/browser_smoke.py --admin-setup
node --check dashboard/bantis_dashboard/static/app.js
git diff --check
```

The automated API/browser tests simulate Docker and external providers. They
cover fixed command arguments, authentication/Origin, duplicate starts,
failures/retries, restart recovery, locking, readiness, redaction, bounded
history, streaming, navigation, mobile layout, and logout. Compose configuration
is validated without starting Docker resources when its CLI is installed.

For a real build/startup/health check using disposable state and free loopback
ports, with no AI calls or use of existing Range credentials:

```bash
range/.venv/bin/python dashboard/scripts/orchestration_smoke.py
```

This optional test copies only runtime sources into a temporary build context,
uses a unique project/image namespace, verifies HTTP health, authenticated
Copilot access and Detection Engine ingestion, then removes only its test
containers and PostgreSQL volume. Built image layers remain cached. It requires
Docker access, image/dependency downloads on first use, and enough disk space.

## API and live updates

| Route | Access | Behavior |
|---|---|---|
| `GET /`, `/setup`, `/live-feed`, `/incidents`, `/audit-log`, `/static/*` | Public shell | Local assets only; contains no incident records, event records, or credentials. |
| `GET /health` | Public | Dashboard process liveness, independent of upstream availability. |
| `POST /api/session` | Dashboard token | Creates an opaque, HttpOnly, SameSite=Strict session cookie. |
| `GET /api/setup` | Public | Reports whether administrator mode is enabled and an account exists; returns no account details. |
| `POST /api/setup/admin` | Bootstrap token + exact Origin | Creates the single administrator once; returns 409 after account creation. Does not issue a session. |
| `POST /api/admin/session` | Administrator credentials + exact Origin | Creates the existing opaque session cookie in administrator mode. |
| `GET /api/setup/services` | Session | Redacted orchestration state, selected service health, and bounded recent logs. Host-disabled mode reports unavailable. |
| `POST /api/setup/services/start` | Administrator session + exact Origin + host opt-in | Starts the fixed service plan asynchronously; duplicate starts share existing work. Requires saved setup choices. |
| `WS /ws/setup/services` | Administrator session + exact Origin + host opt-in | Live redacted startup/service logs and periodic status; revoked on logout or expiry. |
| `GET /api/setup/permissions` | Administrator session | Saved capability choices and encrypted storage readiness. |
| `POST /api/setup/permissions` | Administrator session + exact Origin | Saves encrypted capability choices; clears previous integration test receipts. |
| `GET /api/setup/provider` | Administrator session | Redacted saved provider selection. Requires administrator mode. |
| `POST /api/setup/provider/test` | Administrator session + exact Origin | One real connection test; returns a session-bound receipt on success. |
| `POST /api/setup/provider` | Administrator session + exact Origin | Saves a tested selection, or disables AI without a provider request. |
| `GET /api/setup/telegram` | Administrator session | Redacted saved Telegram selection; requires administrator mode. |
| `POST /api/setup/telegram/test` | Administrator session + exact Origin | Sends one fixed test message and returns a session-bound receipt. |
| `POST /api/setup/telegram` | Administrator session + exact Origin | Saves tested credentials, or skips Telegram and removes the stored token without a network request. |
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
Token mode provides shared local access. Optional administrator mode adds a
single persistent account; neither mode is a multi-user identity system.

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
python dashboard/scripts/browser_smoke.py --python "$PWD/range/.venv/bin/python" --admin-setup
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
The `--admin-setup` variant checks Permissions defaults, save/reload, Back
navigation, mobile layout, and encrypted storage readiness. It also checks Telegram testing, changed-chat invalidation,
private save, reload, back navigation, skipping, mobile layout, and logout using
fixture responses. No real Telegram messages are sent. It also covers password
confirmation, invalid bootstrap authentication, secret clearing, account creation, setup
locking after reload, administrator sign-in, and session persistence across
page reloads, then runs the same dashboard flows. It also checks provider errors,
successful testing, save invalidation after edits, persistence, secret clearing,
and opting out of AI. Test-only injected transports avoid external requests;
production uses the fixed Anthropic and Telegram HTTPS endpoints. API tests additionally cover
process restart, concurrent creation, unavailable state, private file permissions,
rate limiting, logout, and WebSocket revocation.
CI runs API/WebSocket tests on Python 3.12 and 3.14, checks JavaScript syntax,
and includes Detection Engine tests and real query integration in the end-to-end job. Browser
checks are optional and are not configured as a CI job.
Encryption and capability coverage is in `tests/test_secret_store.py` and
`tests/test_permissions_setup.py`. It checks key loss and replacement, tampering,
private permissions, unsafe file types, atomic failures, concurrent key creation,
legacy migration, cross-document substitution, request enforcement, revocation,
and in-flight test invalidation. All tests use disposable state and fixture
external APIs. Run them with `range/.venv/bin/python -m pytest dashboard/tests -q`
from the repository root.