# Purple Team Loop: M2 Scenarios to M3 Incidents

This process turns an M2 attack-sim run that produces no M3 Detection Engine
incident into a tracked improvement and a repeatable verification. It defines
an operator workflow; it does not add automatic gap detection, ticket creation,
notifications, or response execution.

Use the [scenario reference](scenarios.md), [event schema](event-schema.md),
[correlation design](correlation-design.md), and current
[Detection Engine guide](../detection-engine/README.md) together. The
[M3 closure](m3-closure.md) is a historical snapshot; scheduled correlation
and the dashboard have since been added.

## Definition and decision rule

A **detection gap** is a valid execution of one of the four M2 attack scenarios
for which **no persisted M3 incident references that execution's event ID in
`correlated_event_ids` by the recorded observation deadline**. A missing event
in M3 also qualifies when producer-side evidence proves the scenario ran and
identifies the event that should have arrived.

The four scenarios are `malicious-dependency`, `leaked-secret`,
`compromised-ci-step`, and `typosquatting`. A valid execution reaches its
verification step and yields `details.status` of `success` (attack got through)
or `failure` (attack was defended). Both outcomes require coverage review.
`error`, a blocked environment check, or a missing dependency is an invalid
exercise: repair the setup and rerun it before judging detection. `noop` is
outside this definition.

For a valid run R with emitted event IDs E and deadline D:

```text
detected(R, D) = a persisted incident created by D references an ID in E
gap(R, D)      = valid(R) and not detected(R, D)
```

Record each scenario execution separately. An incident may cover multiple
runs, but it covers a particular run only if it references that run's event
ID. A matching scenario name, timestamp, pattern, summary, or MITRE technique
alone is insufficient. If a future scenario emits multiple required signals,
declare their coverage requirements before running it.

| Observation | Classification and next step |
| --- | --- |
| Valid run, no event received by M3 | Telemetry gap: check emission, forwarding, ingestion, and storage. |
| Event stored, completed correlation produces no referencing incident | Rule coverage gap or rule regression: compare with the declared exercise expectation. |
| Event stored, required correlation passes fail or never run | Correlation execution gap: restore scheduling or storage and replay the exercise. |
| Referencing incident exists, but dashboard or Telegram shows nothing | Presentation or notification issue, outside this detection-gap definition. Record separately. Telegram normally alerts only for critical incidents. |
| Scenario is defended and a referencing incident exists | Prevention and detection both worked; there is no detection gap. |
| Scenario errors before a valid outcome | Invalid exercise; preserve the error and rerun after repairing the setup. |
| Referencing incident appears after D | Late detection: retain the missed deadline and original gap record; link the late incident. |

Missing evidence is **inconclusive**, never proof of coverage. Preserve producer
output and event IDs during the exercise so that an ingestion failure can be
distinguished from a scenario that never ran.

## Observation contract

Before execution, record the revision, configuration, scenario, intended
outcome, expected rule (or explicit absence of a dedicated rule), event IDs,
UTC timestamps, and whether this is a batch or scheduled exercise. Use an
isolated lab with `BANTIS_ENV=range-local` and the scenario cleanup contract.
Use a fresh test database or retain exact event IDs so unrelated exercise
events cannot supply an accidental burst partner.

Set the deadline before examining the result:

- **Batch:** after all expected events are ingested, explicitly complete
  `run_correlation(session)` and query the persisted incidents. Record the
  completion time as D. This checks grouping on a complete batch and does not
  measure scheduler latency. If the pass cannot complete, record a correlation
  execution gap at the planned exercise cutoff rather than waiting forever.
- **Scheduled:** record the enabled `CORRELATION_INTERVAL_SECONDS` (I), an
  ingestion allowance (L), and processing allowance (P). Use a conservative
  exercise cutoff `D = last producer emission time + L + 300 seconds + 2*I + P`.
  This assumes a finite exercise with no further eligible traffic from the
  same source after the last emission. The 300 seconds cover composite waiting
  and the 60-second burst quiet period; the two intervals allow scheduling
  and a confirming pass. For a
  local exercise, L=5s, I=10s, P=5s gives 330s after the last emission. These
  are exercise allowances, not a product latency guarantee. Record observed
  server receipt times and completed pass evidence; if an allowance is missed,
  classify the delay instead of extending D after seeing the outcome.

For scheduled exercises, `CORRELATION_INTERVAL_SECONDS=0` disables detection
passes. Enable the scheduler or deliberately select batch mode before running.
Current scheduled correlation uses server receipt time to hold dependency or
secret candidates for up to 300 seconds, and to settle bursts after 60 seconds
of quiet or a 600-second maximum hold during continuing traffic. If other
same-source traffic continues, isolate the exercise or declare a separate
deadline accounting for that hold before execution. Event timestamps still determine rule grouping:
the same-source window is 60 seconds, the composite window is 300 seconds.
Waiting longer does not make events outside those windows eligible.

At D, read `GET /incidents` without severity, pattern, or time filters, page
through all results using `limit` and `offset`, and check exact event-ID
membership. Preserve the response, query time, total, database identity, and
ingestion/pass evidence. Retrieve `GET /incidents/{incident_id}` and
`GET /incidents/{incident_id}/events` for any match. The dashboard and a missing
notification alone cannot establish the absence of an incident.

## Existing coverage and interpretation

The [M2 baseline](m2-detection-baseline.md) runs all four scenarios together:

| Exercise | Current expected result |
| --- | --- |
| Dependency plus secret within 300 seconds | `composite-dependency-secret` references both event IDs, including when both attacks were defended. |
| Compromised CI step plus typosquatting, same source within 60 seconds | `same-source-burst` references both IDs after scheduled settling, provided another rule has not already claimed them. |
| Any one M2 scenario in isolation | No dedicated single-scenario incident rule exists. Record a known coverage gap after the deadline. |
| Invalid `error` outcome | Excluded from correlation; repair the exercise. |

An isolated scenario is an intentional negative case in the current
[rule evaluation](detection-rate-baseline.md). Its lack of an incident can
pass the current implementation tests while still being a coverage gap under
this Purple Team definition. Label it **known coverage limitation**, rather
than changing the existing rule expectation to pretend a regression occurred.
An absent incident that the paired baseline promises is a **regression**.

The baseline's 2/2 expected patterns and 100% detection rate do not prove
independent coverage of four isolated scenarios. Track both pattern-level
scorecards and per-run incident membership. Keep synthetic, fixture-backed,
and live lab results distinct. A prevention failure (`success`) and a detection
gap are separate findings; either can exist without the other.

## Expected response and ownership

The expected response to a gap is an evidence-backed remediation record and a
verified replay, with an explicit owner and next action. A gap record is a
local document or an issue in the team's existing tracker; it is not an M3
incident and must not be inserted into the incident store to improve scores.

| Step | Owner | Required result |
| --- | --- | --- |
| Plan and execute | Exercise operator (Red role) | Declared expectation and deadline, valid run output, event IDs, cleanup result. |
| Observe and register | Detection operator (Blue role) | Incident membership query and evidence; open a gap record when the decision rule is met. |
| Triage together | Red and Blue roles | Reproduce the miss; classify telemetry, correlation execution, rule regression, or known coverage limitation; assign priority, owner, and due date. |
| Repair | Assigned component maintainer | Correct producer/transport/storage/scheduling/rule behavior, or propose a scoped new rule with benign negative cases. Link the change and regression check. |
| Verify | Detection operator, reviewed by exercise operator | Repeat the original conditions, verify persisted event-ID membership and declared pattern, check noise and cleanup, attach before/after evidence. |
| Close or accept | Exercise lead | Close only with passing replay evidence, or record a time-limited risk acceptance with rationale, approver, review date, and compensating control. |

One local operator may fill all roles, but must record who performed each step.
At exercise review, assign every open gap an owner, target date, and next
checkpoint. Prioritize a successful attack without an incident and regressions
of promised coverage ahead of a defended attempt with a documented coverage
limitation. Record impact and exposure explicitly; priority is a triage choice,
not the incident severity or confidence score.

First locate the earliest failed boundary: scenario verification → event
emission → HTTP forwarding/acceptance → stored event → correlation pass →
persisted incident membership. Inspect producer stderr as well as HTTP results:
forwarding failures can be swallowed by logging. Preserve the original event
IDs and timestamps; reruns need fresh IDs to avoid duplicate ingestion and
prior event claims. Do not add an unrelated second scenario just to make the
original isolated miss appear detected.

A gap alone does not authorize containment or any Response Controller action.
Copilot recommendations cannot repair missing M3 incidents. Any operational
response follows the existing [controller policy and approval
controls](response-controller-security.md); this loop produces detection work
and verification evidence.

### Gap record template

Copy this template for each miss; replace placeholders with observed values.
Do not include real credentials or unredacted tool output.

```text
Gap ID / title:
State: open | triaged | remediation | verification | closed | risk-accepted
Scenario / MITRE technique / revision / environment:
Exercise mode / configuration / database identity:
Producer outcome (success or failure) / verification evidence:
Event IDs / emitted UTC / received UTC (or missing):
Expected coverage / rule / baseline reference:
Deadline UTC / L / I / P (scheduled) or completed batch pass:
Observed incident IDs: none, or IDs with exact event membership
Evidence: producer output, ingestion result, stored event, pass logs,
          paginated incident query and observation time
Classification: telemetry | correlation execution | rule regression |
                known coverage limitation
Impact / priority / rationale:
Root cause / remediation hypothesis:
Owner / target date / next checkpoint:
Change reference / regression check / benign negative cases:
Retest run IDs / new event IDs / incident IDs / before-and-after result:
Cleanup result:
Closure reviewer and date, or risk approver / rationale / review date /
compensating control:
```

Keep accepted gaps visible in the coverage inventory; risk acceptance is not
successful detection. Reopen a closed gap if the same conditions miss again.

## Verification and closure criteria

Review these cases when applying the workflow:

1. A paired M2 baseline produces both expected patterns and all four run IDs
   are represented through their event IDs: no gap.
2. An isolated valid `compromised-ci-step` produces an event but no incident:
   open a known coverage limitation, even if a different run has an incident.
3. A valid defended attempt loses its forwarding event: open a telemetry gap;
   prevention did not establish detection.
4. A missing tool produces `error`: repair and rerun, without claiming a miss.
5. Scheduled correlation has not reached its hold deadline: keep observing;
   failed or disabled passes at the cutoff require correlation execution triage.
6. A matching incident is on a later API page: it counts as detection. A
   dashboard delay or missing high-severity Telegram message does not undo it.
7. A fix replays the original isolated conditions and produces the declared
   referencing incident within D: verify benign cases and close. Adding a burst
   partner, changing the deadline afterward, or accepting risk cannot satisfy
   this closure condition. A late incident retains a latency finding until a
   fresh replay meets the agreed deadline.

Existing checks, run from the repository root with component dependencies
installed, validate current rules, scheduling, and scorecards:

```bash
range/.venv/bin/python detection-engine/tests/evaluate_correlation_rules.py
(cd detection-engine && ../range/.venv/bin/python -m pytest tests/test_correlation.py tests/test_scheduler.py tests/test_scorecard.py -q)
git diff --check
```

These checks do not automate the gap workflow or assert that isolated scenarios
are now detected. A future remediation must add a check for its exact original
miss and suitable benign cases, then repeat the exercise with fresh event IDs.