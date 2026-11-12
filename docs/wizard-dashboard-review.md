# Wizard and Dashboard Design Review

Review against the [design baseline](wizard-dashboard-design.md). This checklist
is acceptance guidance for the full UI. The administrator step and existing
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