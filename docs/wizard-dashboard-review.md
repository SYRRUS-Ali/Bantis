# Wizard and Dashboard Design Review

Review against the [design baseline](wizard-dashboard-design.md). This checklist
is acceptance guidance for the full UI. The administrator, Permissions, AI provider, optional Telegram, and service startup steps and existing
dashboard have executable tests; the remaining wizard steps are future work.

## Reference review before design freeze

- [ ] Attach the agreed wizard diagram and identify its revision.
- [ ] Attach the agreed dashboard diagram and identify its revision.
- [ ] Map every diagram screen to the design baseline; resolve differences in
  step order, navigation, page composition, and responsive behavior.
- [ ] Record exact labels, layout, visual specifications, and all deviations.
- [ ] Record the reviewer, date, and accepted design revision in the baseline.

The design stays Draft until these items are complete. Backend gaps may remain
after a layout freeze, but must retain explicit unavailable states and tracked
implementation requirements.

## Wizard acceptance scenarios

| Check | Expected result |
|---|---|
| First setup | Required checks and administrator setup follow the agreed flow; completion requires successful mandatory checks. |
| Invalid connection | The failed field or service has an actionable message; no false completion state appears. |
| Back, retry, or duplicate submit | Non-sensitive inputs survive navigation; retries do not duplicate configuration or accounts. |
| Missing provider key | Setup can finish with a clearly labeled Copilot unavailable state. |
| Credential review | Secrets are redacted and absent from URLs, logs, and durable browser storage. |
| Finish setup | Actions remain disabled, dry run stays enabled, and automatic response stays off. |
| Reload or second setup session | Transactional singleton creation prevents overwriting an established administrator. A completed creation shows sign-in; an interrupted transaction can be retried after checking setup status. |
| Administrator authentication | Creation requires the bootstrap token and exact Origin; subsequent access requires the stored account credentials. Token login cannot bypass administrator mode. |
| Permissions | Optional capabilities default off in administrator mode. Save/reload preserves choices; unauthorized or cross-origin writes fail. Revoking a capability blocks subsequent requests and invalidates earlier integration tests, including in-flight results. |
| Controller boundary | Enabling manual decisions requires host-enabled review and keeps the separate operator secret and controller policy. No action, dry-run, automatic-execution, or stop settings are written. |
| Encrypted storage | Ciphertext contains no plaintext integration secrets. Private key/configuration files survive restart; wrong, missing, public, symlinked, or tampered files fail closed without replacing the key. Valid legacy provider/Telegram files migrate atomically. |
| Provider connection | Claude testing sends a real bounded provider request; invalid keys, inaccessible models, timeouts, malformed responses, and rate limits cannot report success. Tests are not retried automatically. |
| Provider save | Saving Claude requires an unexpired test receipt from the same session. Changed settings require a new test. No AI can be saved without credentials or a network request. |
| Provider secrets and restart | Keys are absent from retrieval, errors, and browser storage. Private saved settings survive restart and are loaded by Copilot at startup; invalid files cannot silently fall back to an environment key. |

Telegram acceptance also requires: skipping without credentials or a network
request; one fixed test message before enabled save; actionable sanitized errors;
invalidating receipts after edits, expiry, logout, or session rotation; preserving
the chat ID on Back; redacting tokens in retrieval and HTTPX logs; private atomic
storage; and persistence of both enabled and skipped selections after restart.
Automatic incident notification delivery is outside this step.

Service startup acceptance also requires: a host opt-in and administrator session;
exact Origin and fixed request fields; validated saved setup choices; dependency
health checks; no duplicate launches; actionable failure and explicit retry;
reconciliation after dashboard restart; one coordinator per state directory;
redacted bounded live logs; history-gap/stale notices; safe text rendering;
stream revocation on logout; and a fresh successful status before showing the
startup completion link. Service startup must not grant response authorization,
launch attack simulations, reset volumes, or stop unrelated services.

## Dashboard acceptance scenarios

| Check | Expected result |
|---|---|
| List, filter, paginate, open, return | API-supported filters and matching total are accurate; returning preserves list position and filters. |
| Equal evidence timestamps | Event ID provides deterministic ordering; all correlated evidence remains accessible. |
| Missing incident | Show a clear missing-record state and a route back to the list. |
| Provider failure or absent analysis | Incidents remain visible; Copilot state is explicit and never presented as a clean verdict. |
| Confidence values | Detection and AI confidence have separate labels and sources. |
| Follow-up question | An authorized question uses the recorded incident context; unavailable analysis prevents submission with an explanation. |
| Unsupported response action | Browser control is unavailable and explains the CLI or missing implementation. |
| Modified or expired proposal | An obsolete approval cannot execute; modifications require fresh approvals. |
| Dry run and live success | Labels distinguish a plan without target mutation from a verified effect. |
| Stop and recovery | Stop does not require approval; show actual stop and audit results, preserve independent AI state, and offer no unimplemented resume. |
| Refresh failure | Last successful data remains labeled stale; an outage never becomes a zero count. |
| Untrusted content | HTML-like incident or model text renders without script execution. |
| Keyboard and narrow screen | Forms and navigation work without a pointer; status remains understandable without color; review details stay readable. |

Exercise mutation scenarios against isolated fixtures when the UI and its
authenticated APIs exist. Never use production response actions merely to
validate a design document.

## Documentation checks

From the repository root, run `git diff --check` and inspect both documents in a
Markdown preview that supports Mermaid. Confirm links resolve, the flow renders,
all added text is English, and no draft layout is called approved. Compare the
data-source table with the linked component guides and
[M5 limitations](m5-closure.md#known-limitations).

Administrator-step coverage is in [test_admin.py](../dashboard/tests/test_admin.py)
and the `--admin-setup` variant of the
[browser check](../dashboard/scripts/browser_smoke.py). These verify creation,
credential validation, persistence, concurrent submissions, setup locking,
session behavior, rate limiting, private storage, and the browser step. They do
not establish readiness of the remaining wizard steps or final visual approval.

Provider coverage is in
[test_provider_setup.py](../dashboard/tests/test_provider_setup.py),
[test_provider_configuration.py](../ai-copilot/tests/test_provider_configuration.py),
and the same browser variant. Automated checks use fixture provider responses
and incur no external charges. A live account check uses the implemented
**Test connection** control with an operator-supplied API key.

Telegram API coverage is in
[test_telegram_setup.py](../dashboard/tests/test_telegram_setup.py), with browser
coverage in the `--admin-setup` variant. Automated tests use Telegram fixture
responses and send no real messages. To check actual delivery, use **Send test
message** with your own bot and chat, confirm the fixed message arrived, then
save or skip the optional integration.

Permissions and encryption coverage is in
[test_permissions_setup.py](../dashboard/tests/test_permissions_setup.py),
[test_secret_store.py](../dashboard/tests/test_secret_store.py), and the updated
Copilot configuration tests. The browser variant begins at **Setup → Permissions**
and verifies defaults, save/reload, navigation, readiness status, and mobile layout.
See [run and inspect instructions](../dashboard/README.md#run-and-inspect-this-step)
for a local walkthrough.

Orchestration coverage is in
[test_orchestration.py](../dashboard/tests/test_orchestration.py),
[test_services_api.py](../dashboard/tests/test_services_api.py), and
[test_compose_definition.py](../dashboard/tests/test_compose_definition.py).
The browser check includes failure/retry, live text logs, filtering, pause/resume,
clear view, navigation, and mobile layout. The optional
[Docker smoke test](../dashboard/scripts/orchestration_smoke.py) builds an isolated
stack, checks real service health and ingestion with AI disabled, and removes
only its disposable resources. See the [launch guide](../dashboard/README.md#service-orchestration-and-live-logs).