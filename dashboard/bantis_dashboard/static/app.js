"use strict";

const $ = (id) => document.getElementById(id);
const access = { mode: "loading", setupBusy: false };
const isAuditLog = location.pathname === "/audit-log";
const isIncidents = location.pathname === "/incidents";
const isLiveFeed = location.pathname === "/live-feed";
const connectionLabel = () => $(isLiveFeed ? "live-connection" : "connection-label");
const live = { snapshot: null, displayed: [], paused: false, cleared: new Set(),
  clearedView: false, pauseTotal: null, gap: false, request: 0 };
$("overview-content").hidden = isLiveFeed || isAuditLog;
$("audit-log-view").hidden = !isAuditLog;
$("live-feed-view").hidden = !isLiveFeed;
$("page-name").textContent = isLiveFeed ? "Live feed" : isIncidents ? "Incidents" : isAuditLog ? "Audit log" : "Overview";
if (isIncidents) {
  $("overview-title").textContent = "Incidents.";
  $("overview-subtitle").textContent = "Investigate correlated signals with evidence and recorded AI context.";
}
document.title = isLiveFeed ? "Bantis · Live feed" : isIncidents ? "Bantis · Incidents" : isAuditLog ? "Bantis · Audit log" : "Bantis · Security overview";
document.querySelector(`[data-page="${isLiveFeed ? "live-feed" : isIncidents ? "incidents" : isAuditLog ? "audit-log" : "overview"}"]`).setAttribute("aria-current", "page");
const state = { offset: 0, limit: 20, total: 0, filters: {}, socket: null, retry: null,
  delay: 1000, active: false, listRequest: 0, detailRequest: 0, lastList: null, snapshot: null,
  listController: null, detailController: null, lastSequence: -1, listBusy: false };

const investigation = { id: null, request: 0, controller: null, canAsk: false, asking: false, lastLoaded: null };
const reviewState = { request: 0, busy: false };

function resetInvestigation() {
  reviewState.request++; reviewState.busy = false;
  $("response-panel").hidden = true;
  $("response-proposals").replaceChildren(); $("response-notice").textContent = "";
  $("response-refresh").disabled = false;
  investigation.request++; investigation.controller?.abort();
  investigation.id = null; investigation.canAsk = false; investigation.asking = false; investigation.lastLoaded = null;
  $("analysis-panel").hidden = true;
  $("analysis-content").replaceChildren(); $("conversation").replaceChildren();
  $("analysis-notice").textContent = ""; $("conversation-notice").textContent = "";
  $("question").value = ""; $("question").disabled = true;
  $("ask-question").disabled = true; $("ask-question").textContent = "Send question";
  $("analysis-refresh").disabled = false;
  $("incident-dialog").classList.remove("investigating");
}

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function time(value) {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}
function stopSocket() {
  clearTimeout(state.retry);
  state.retry = null;
  if (state.socket) { state.socket.onclose = null; state.socket.close(); state.socket = null; }
}
function signedOut() {
  state.active = false;
  resetInvestigation();
  resetAuditLog();
  stopSocket();
  state.listRequest++; state.detailRequest++;
  state.listController?.abort(); state.detailController?.abort();
  state.lastList = null; state.snapshot = null; state.offset = 0; state.total = 0;
  state.lastSequence = -1;
  state.listBusy = false;
  live.request++; live.snapshot = null; live.displayed = []; live.cleared.clear();
  live.paused = false; live.gap = false; live.clearedView = false;
  $("live-rows").replaceChildren();
  $("live-count").textContent = "—"; $("live-matching").textContent = "—";
  $("live-pause").textContent = "Pause display"; $("live-pause").setAttribute("aria-pressed", "false");
  $("incident-rows").replaceChildren(); $("detail-content").replaceChildren();
  $("incident-dialog").close();
  $("total-incidents").textContent = "—";
  $("workspace").hidden = true;
  $("login-screen").hidden = access.mode === "setup";
  $("setup-screen").hidden = access.mode !== "setup";
  $("access-token").value = "";
  $("admin-password").value = "";
  $("setup-token").value = ""; $("setup-password").value = ""; $("setup-confirmation").value = "";
  $(access.mode === "admin" ? "admin-username" : access.mode === "setup" ? "setup-token" : "access-token").focus();
}
async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  if (response.status === 401 && !(["/api/session", "/api/admin/session"].includes(path) && options.method === "POST")) {
    signedOut(); throw new Error("Session expired. Please sign in again.");
  }
  if (!response.ok) {
    let message = "Request failed. Try again.";
    try { const data = await response.json(); if (typeof data.detail === "string") message = data.detail; } catch {}
    throw new Error(message);
  }
  return response.json();
}
function pagination() {
  $("previous").disabled = state.offset === 0;
  $("next").disabled = state.offset + state.limit >= state.total;
}
async function loadIncidents() {
  const request = ++state.listRequest;
  state.listBusy = true;
  state.listController?.abort();
  state.listController = new AbortController();
  const params = new URLSearchParams({ ...state.filters, limit: state.limit, offset: state.offset });
  $("list-notice").textContent = state.lastList ? "Refreshing incidents…" : "Loading incidents…";
  $("list-notice").className = "notice";
  try {
    const page = await api(`/api/incidents?${params}`, { signal: state.listController.signal });
    if (request !== state.listRequest || !state.active) return;
    state.total = page.total;
    if (state.offset > 0 && state.offset >= page.total) {
      state.offset = Math.max(0, Math.floor((page.total - 1) / state.limit) * state.limit);
      return loadIncidents();
    }
    const rows = page.items.map((incident) => {
      const row = node("tr");
      const severity = node("td"); severity.append(node("span", incident.severity, `pill ${incident.severity}`));
      const description = node("td");
      const link = node("button", incident.summary, "incident-link");
      link.type = "button"; link.addEventListener("click", () => showIncident(incident.incident_id));
      description.append(link, node("span", incident.pattern, "pattern-label"));
      row.append(severity, description, node("td", incident.mitre_techniques.join(", ") || "—"),
        node("td", `${Math.round(incident.confidence * 100)}%`), node("td", time(incident.created_at)));
      return row;
    });
    $("incident-rows").replaceChildren(...rows);
    state.lastList = new Date().toISOString();
    $("list-notice").textContent = page.total ? `Last loaded ${time(state.lastList)}` : "No incidents match these filters.";
    $("page-label").textContent = page.total ? `${page.offset + 1}–${page.offset + page.items.length} of ${page.total} matching incidents` : "0 matching incidents";
    pagination();
  } catch (error) {
    if (request !== state.listRequest || error.name === "AbortError" || !state.active) return;
    $("list-notice").textContent = `${error.message}${state.lastList ? ` Showing stale data from ${time(state.lastList)}.` : " No incident data loaded."}`;
    $("list-notice").className = "notice error";
  } finally {
    if (request === state.listRequest) state.listBusy = false;
  }
}
function renderSnapshot(snapshot) {
  if (!state.active) return;
  state.snapshot = snapshot;
  const engine = snapshot.detection_engine;
  $("engine-status").textContent = { available: "Available", unavailable: "Unavailable", connecting: "Connecting" }[engine.status];
  $("total-incidents").textContent = engine.total_incidents === null ? "—" : String(engine.total_incidents);
  $("total-caption").textContent = engine.status === "available" ? "Across this environment" : "Awaiting current data · values may be stale";
  $("last-refresh").textContent = snapshot.last_success_at ? `Last observed ${time(snapshot.last_success_at)}` : "Awaiting first successful observation";
  if (state.socket?.readyState === WebSocket.OPEN) {
    $("connection-label").textContent = engine.status === "available" ? "Live connection · periodic updates" : "Live connection · Detection Engine unavailable";
  }
}
function connect() {
  if (!state.active) return;
  stopSocket();
  connectionLabel().textContent = "Connecting to live updates…";
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}${isLiveFeed ? "/ws/events" : "/ws"}`);
  state.socket = socket;
  socket.onopen = () => { state.delay = 1000; connectionLabel().textContent = "Live connection · awaiting observation"; };
  socket.onmessage = (event) => {
    let snapshot;
    if (state.socket !== socket || !state.active) return;
    try { snapshot = JSON.parse(event.data); } catch { return; }
    if (isLiveFeed && snapshot.type === "events.snapshot") { renderLiveSnapshot(snapshot); return; }
    if (snapshot.type !== "dashboard.snapshot") return;
    renderSnapshot(snapshot);
    if (snapshot.sequence !== state.lastSequence) {
      state.lastSequence = snapshot.sequence;
      // Manual refreshes and filter changes take precedence over the next periodic read.
      if (!state.listBusy) loadIncidents();
    }
  };
  socket.onclose = async () => {
    if (!state.active) return;
    connectionLabel().textContent = "Live connection lost · displayed data may be stale · reconnecting…";
    if (isLiveFeed) renderLiveEvents();
    try { await api("/api/session"); } catch { if (!state.active) return; }
    state.lastSequence = -1;
    state.retry = setTimeout(connect, state.delay);
    state.delay = Math.min(state.delay * 2, 30000);
  };
  socket.onerror = () => socket.close();
}
async function activate() {
  state.active = true; state.delay = 1000;
  $("login-screen").hidden = true; $("workspace").hidden = false;
  $("login-error").textContent = "";
  if (isAuditLog) { loadAuditLog(); return; }
  if (isLiveFeed) { refreshLiveFeed(); connect(); return; }
  loadIncidents(); connect();
  try { renderSnapshot(await api("/api/status")); } catch {}
}
async function showIncident(id) {
  resetInvestigation();
  investigation.id = id;
  $("analysis-panel").hidden = false;
  $("incident-dialog").classList.add("investigating");
  const request = ++state.detailRequest;
  state.detailController?.abort(); state.detailController = new AbortController();
  const options = { signal: state.detailController.signal };
  $("detail-content").replaceChildren(); $("detail-title").textContent = "Incident detail";
  $("detail-kind").textContent = "INCIDENT INVESTIGATION";
  $("detail-notice").textContent = "Loading incident and evidence…";
  if (!$("incident-dialog").open) $("incident-dialog").showModal();
  try {
    const incident = await api(`/api/incidents/${encodeURIComponent(id)}`, options);
    if (request !== state.detailRequest || !state.active) return;
    $("detail-title").textContent = incident.summary;
    loadAnalysis();
    loadProposals();
    const facts = node("dl");
    for (const [label, value] of [["Incident ID", incident.incident_id], ["Severity", incident.severity],
      ["Pattern", incident.pattern], ["Created", time(incident.created_at)],
      ["Detection confidence", `${Math.round(incident.confidence * 100)}%`],
      ["MITRE techniques", incident.mitre_techniques.join(", ") || "—"], ["Correlation window", `${incident.window_seconds} seconds`]]) {
      facts.append(node("dt", label), node("dd", value));
    }
    $("detail-content").append(facts, node("h3", "Evidence timeline"));
    const events = await api(`/api/incidents/${encodeURIComponent(id)}/events`, options);
    if (request !== state.detailRequest || !state.active) return;
    for (const event of events) {
      const entry = node("article", undefined, "evidence-entry");
      entry.append(node("p", `${time(event.timestamp)} · ${event.source} · ${event.event_type}`),
        node("p", `Event ${event.event_id}`), node("pre", JSON.stringify(event.details, null, 2)));
      $("detail-content").append(entry);
    }
    if (!events.length) $("detail-content").append(node("p", "No correlated evidence returned."));
    $("detail-notice").textContent = "Selected evidence fields are shown. Raw messages and tool output are omitted.";
  } catch (error) {
    if (request === state.detailRequest && error.name !== "AbortError" && state.active) $("detail-notice").textContent = error.message;
  }
}
async function loadProposals(message = "") {
  if (!investigation.id || reviewState.busy) return;
  const id = investigation.id, request = ++reviewState.request;
  const current = () => state.active && investigation.id === id && reviewState.request === request;
  $("response-panel").hidden = false;
  $("response-refresh").disabled = true;
  $("response-proposals").replaceChildren();
  $("response-notice").textContent = message || "Loading controller proposals…";
  try {
    const page = await api(`/api/incidents/${encodeURIComponent(id)}/proposals`);
    if (!current()) return;
    $("response-notice").textContent = `${message ? message + " " : ""}${page.dry_run ? "Dry run: approval records a plan without acting." : "LIVE mode: approval may execute the action."} ${page.items.length ? "" : "No pending controller proposals for this incident."}`;
    for (const proposal of page.items) {
      const form = node("form", undefined, "evidence-entry");
      form.append(node("h3", proposal.type.replaceAll("_", " ")));
      const facts = node("dl");
      for (const [label, value] of [["Action ID", proposal.action_id], ["Proposal hash", proposal.proposal_hash],
        ["Policy rule", proposal.policy_rule], ["Expires", time(proposal.expires_at)],
        ["Required distinct reviewers", proposal.required_approvals]]) {
        facts.append(node("dt", label), node("dd", String(value)));
      }
      form.append(facts, node("h4", "Current parameters"), node("pre", JSON.stringify(proposal.params, null, 2)));
      const paramsLabel = node("label", "Replacement parameters (JSON object, used by Modify)");
      const params = node("textarea"); params.rows = 3; params.maxLength = 8000;
      params.value = JSON.stringify(proposal.params, null, 2); paramsLabel.append(params);
      const reasonLabel = node("label", "Reason (required for Modify and Dismiss)");
      const reason = node("textarea"); reason.rows = 2; reason.maxLength = 2000; reasonLabel.append(reason);
      const secretLabel = node("label", "Operator approval secret");
      const secret = node("input"); secret.type = "password"; secret.required = true; secret.maxLength = 512;
      secret.autocomplete = "off"; secretLabel.append(secret);
      form.append(paramsLabel, reasonLabel, secretLabel);
      for (const operation of ["approve", "modify", "dismiss"]) {
        const button = node("button", operation[0].toUpperCase() + operation.slice(1), "secondary");
        button.type = "submit"; button.value = operation; form.append(button);
      }
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!current() || reviewState.busy) return;
        const operation = event.submitter?.value;
        if (!operation) return;
        if (operation !== "approve" && !reason.value.trim()) {
          $("response-notice").textContent = "Enter a reason for this decision."; reason.focus(); return;
        }
        let replacement = {};
        if (operation === "modify") {
          try {
            replacement = JSON.parse(params.value);
            if (!replacement || Array.isArray(replacement) || typeof replacement !== "object") throw new Error();
          } catch { $("response-notice").textContent = "Replacement parameters must be a JSON object."; params.focus(); return; }
        }
        const body = JSON.stringify({ operation, action_id: proposal.action_id, proposal_hash: proposal.proposal_hash,
          secret: secret.value, reason: reason.value.trim(), params: replacement });
        secret.value = "";
        reviewState.busy = true; $("response-refresh").disabled = true;
        $("response-proposals").querySelectorAll("input, textarea, button").forEach((control) => { control.disabled = true; });
        $("response-notice").textContent = "Submitting decision to the Response Controller…";
        try {
          const result = await api(`/api/incidents/${encodeURIComponent(id)}/review`, {
            method: "POST", headers: { "Content-Type": "application/json" }, body,
          });
          if (!current()) return;
          reviewState.busy = false;
          const outcome = `Controller result: ${result.status.replaceAll("_", " ")}.${result.reasons?.length ? " " + result.reasons.join("; ") : ""}${result.replacement_id ? " Replacement " + result.replacement_id + " requires fresh approval." : ""}`;
          await loadProposals(outcome);
        } catch (error) {
          if (current()) $("response-notice").textContent = `${error.message} Refresh proposals and audit log before retrying; the decision may already have been recorded.`;
        } finally {
          if (current()) { reviewState.busy = false; $("response-refresh").disabled = false; }
        }
      });
      $("response-proposals").append(form);
    }
  } catch (error) {
    if (current()) $("response-notice").textContent = `${message ? message + " " : ""}${error.message}`;
  } finally {
    if (current()) $("response-refresh").disabled = false;
  }
}
$("response-refresh").addEventListener("click", () => loadProposals());

function renderAnalysis(record) {
  const content = $("analysis-content"); content.replaceChildren();
  const labels = { analyzed: "Analysis recorded", skipped: "Analysis skipped", failed: "Stored analysis failed", not_recorded: "No analysis recorded" };
  content.append(node("p", labels[record.status], "pill neutral"));
  if (record.status === "not_recorded") {
    content.append(node("p", "No decision is recorded yet. Pending work, deferral, and provider outages cannot be distinguished from this record. Refresh to check again."));
  }
  if (record.note) content.append(node("p", record.note, "analysis-text"));
  if (record.recorded_at) {
    const facts = node("dl");
    for (const [label, value] of [["Recorded", time(record.recorded_at)], ["Record ID", record.record_id], ["Model", record.model], ["Outcome", record.outcome]]) {
      facts.append(node("dt", label), node("dd", value || "Unavailable"));
    }
    content.append(facts);
  }
  if (record.analysis) {
    const analysis = record.analysis;
    content.append(node("h3", "Reasoning"), node("p", analysis.reasoning, "analysis-text"));
    const facts = node("dl");
    facts.append(node("dt", "AI confidence"), node("dd", `${Math.round(analysis.confidence * 100)}% · separate from detection confidence`),
      node("dt", "Generated"), node("dd", time(analysis.generated_at)), node("dt", "Analysis model"), node("dd", analysis.model));
    content.append(facts, node("h3", "Recommendation"), node("p", analysis.proposed_action.type.replaceAll("_", " "), "pill neutral"),
      node("p", analysis.proposed_action.description, "analysis-text"));
  }
}
function renderConversation(records) {
  $("conversation").replaceChildren(...records.map((record) => {
    const entry = node("article", undefined, "conversation-entry");
    entry.append(node("p", `${time(record.asked_at)} · ${record.model}`, "fine-print"),
      node("h4", "Question"), node("p", record.question, "analysis-text"), node("h4", "Answer"), node("p", record.answer, "analysis-text"));
    return entry;
  }));
}
async function loadAnalysis() {
  if (!investigation.id || investigation.asking) return;
  const id = investigation.id;
  const request = ++investigation.request;
  investigation.controller?.abort(); investigation.controller = new AbortController();
  const options = { signal: investigation.controller.signal };
  const current = () => state.active && investigation.id === id && investigation.request === request;
  investigation.canAsk = false; $("ask-question").disabled = true; $("question").disabled = true;
  $("analysis-refresh").disabled = true;
  $("analysis-notice").textContent = "Loading recorded analysis…";
  $("conversation-notice").textContent = "Waiting for analysis…";
  try {
    const record = await api(`/api/incidents/${encodeURIComponent(id)}/analysis`, options);
    if (!current()) return;
    renderAnalysis(record);
    investigation.lastLoaded = new Date().toISOString();
    $("analysis-notice").textContent = `Last loaded ${time(investigation.lastLoaded)}`;
    if (record.status === "not_recorded") {
      $("conversation").replaceChildren();
      $("conversation-notice").textContent = "Questions require a successful recorded analysis.";
      return;
    }
    $("conversation-notice").textContent = "Loading conversation…";
    try {
      const records = await api(`/api/incidents/${encodeURIComponent(id)}/questions`, options);
      if (!current()) return;
      renderConversation(records);
      $("conversation-notice").textContent = records.length ? `${records.length} recorded ${records.length === 1 ? "reply" : "replies"}` : "No follow-up questions yet.";
      investigation.canAsk = record.status === "analyzed" && record.can_ask;
      if (!investigation.canAsk) $("conversation-notice").textContent += " Questions require a successful recorded analysis.";
    } catch (error) {
      if (current() && error.name !== "AbortError") $("conversation-notice").textContent = `${error.message} Displayed conversation may be stale. Refresh before asking again.`;
    }
  } catch (error) {
    if (current() && error.name !== "AbortError") {
      $("analysis-notice").textContent = `${error.message}.${investigation.lastLoaded ? ` Showing stale analysis loaded ${time(investigation.lastLoaded)}.` : " No analysis loaded."}`;
      $("conversation-notice").textContent = "Conversation unavailable. Refresh analysis to reconnect.";
    }
  } finally {
    if (current()) {
      $("analysis-refresh").disabled = false;
      $("question").disabled = !investigation.canAsk;
      $("ask-question").disabled = !investigation.canAsk;
    }
  }
}
$("analysis-refresh").addEventListener("click", loadAnalysis);
$("question-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const question = $("question").value.trim();
  if (!question || !investigation.canAsk || investigation.asking) return;
  const id = investigation.id, request = investigation.request;
  investigation.asking = true;
  $("ask-question").disabled = true; $("question").disabled = true; $("analysis-refresh").disabled = true;
  $("ask-question").textContent = "Waiting for reply…";
  $("conversation-notice").textContent = "Sending question. The provider may take a moment…";
  try {
    await api(`/api/incidents/${encodeURIComponent(id)}/questions`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question }),
      signal: investigation.controller.signal,
    });
    if (investigation.id !== id || investigation.request !== request || !state.active) return;
    $("question").value = "";
    investigation.asking = false;
    await loadAnalysis();
  } catch (error) {
    if (investigation.id !== id || investigation.request !== request || !state.active) return;
    investigation.canAsk = false;
    $("conversation-notice").textContent = `${error.message} Refresh the conversation before retrying; the question may already have been recorded.`;
  } finally {
    if (investigation.id === id && investigation.request === request && state.active) {
      investigation.asking = false;
      $("analysis-refresh").disabled = false;
      $("ask-question").disabled = !investigation.canAsk; $("question").disabled = !investigation.canAsk;
    }
    if (investigation.id === id) $("ask-question").textContent = "Send question";
  }
});

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button"); button.disabled = true;
  const token = $("access-token").value; $("access-token").value = "";
  const credentials = { username: $("admin-username").value, password: $("admin-password").value };
  $("admin-password").value = "";
  try {
    await api(access.mode === "admin" ? "/api/admin/session" : "/api/session", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(access.mode === "admin" ? credentials : { token }),
    });
    await activate();
  } catch (error) { $("login-error").textContent = error.message; }
  finally { button.disabled = false; }
});

async function loadAccess() {
  $("access-retry").hidden = true;
  try {
    const status = await api("/api/setup");
    access.mode = status.enabled ? status.admin_created ? "admin" : "setup" : "token";
    $("setup-screen").hidden = access.mode !== "setup";
    $("login-screen").hidden = access.mode === "setup";
    $("login-form").hidden = access.mode === "setup";
    $("token-fields").hidden = access.mode !== "token";
    $("admin-fields").hidden = access.mode !== "admin";
    $("access-token").disabled = access.mode !== "token";
    for (const id of ["admin-username", "admin-password"]) {
      $(id).disabled = access.mode !== "admin"; $(id).required = access.mode === "admin";
    }
    $("login-description").textContent = access.mode === "admin" ? "Sign in with your administrator account." : "Sign in with the dashboard access token configured on this host.";
    return true;
  } catch (error) {
    $("login-screen").hidden = false; $("setup-screen").hidden = true;
    $("login-form").hidden = true;
    $("login-description").textContent = "Sign-in options are unavailable.";
    $("login-error").textContent = error.message;
    $("access-retry").hidden = false;
    return false;
  }
}
$("access-retry").addEventListener("click", loadAccess);
$("setup-refresh").addEventListener("click", () => { if (!access.setupBusy) loadAccess(); });
$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (access.setupBusy) return;
  const password = $("setup-password").value;
  if (!password.trim() || password !== $("setup-confirmation").value) {
    $("setup-notice").textContent = "Passwords must match and must not be blank."; return;
  }
  const body = JSON.stringify({ username: $("setup-username").value, password,
    password_confirmation: $("setup-confirmation").value, bootstrap_token: $("setup-token").value });
  $("setup-token").value = ""; $("setup-password").value = ""; $("setup-confirmation").value = "";
  access.setupBusy = true;
  $("setup-form").querySelectorAll("input, button").forEach((control) => { control.disabled = true; });
  $("setup-refresh").disabled = true;
  $("setup-notice").textContent = "Creating administrator…";
  try {
    const result = await api("/api/setup/admin", { method: "POST", headers: { "Content-Type": "application/json" }, body });
    $("admin-username").value = result.username;
    $("login-error").textContent = "";
    if (await loadAccess()) {
      $("login-description").textContent = "Administrator created. Sign in to continue.";
      $("admin-password").focus();
    }
  } catch (error) {
    $("setup-notice").textContent = `${error.message} Check setup status before retrying; the account may already have been created.`;
  } finally {
    access.setupBusy = false;
    $("setup-form").querySelectorAll("input, button").forEach((control) => { control.disabled = false; });
    $("setup-refresh").disabled = false;
  }
});
$("sign-out").addEventListener("click", async () => {
  try { await api("/api/session", { method: "DELETE" }); signedOut(); }
  catch (error) { if (state.active) connectionLabel().textContent = `Sign out failed: ${error.message}`; }
});
$("filters").addEventListener("submit", (event) => {
  event.preventDefault(); state.offset = 0; state.filters = {};
  if ($("severity").value) state.filters.severity = $("severity").value;
  if ($("pattern").value.trim()) state.filters.pattern = $("pattern").value.trim();
  if ($("since").value) state.filters.since = new Date(`${$("since").value}Z`).toISOString();
  loadIncidents();
});
$("filters").addEventListener("reset", () => { state.offset = 0; state.filters = {}; loadIncidents(); });
$("previous").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadIncidents(); });
$("next").addEventListener("click", () => { state.offset += state.limit; loadIncidents(); });
$("refresh").addEventListener("click", async () => {
  loadIncidents();
  try { renderSnapshot(await api("/api/status")); } catch (error) { if (state.active) $("connection-label").textContent = error.message; }
});
$("close-detail").addEventListener("click", () => $("incident-dialog").close());
$("incident-dialog").addEventListener("close", () => { state.detailRequest++; state.detailController?.abort(); resetInvestigation(); });

function renderLiveSnapshot(snapshot) {
  if (!state.active) return;
  if (live.snapshot?.observed_at && (!snapshot.observed_at || Date.parse(snapshot.observed_at) < Date.parse(live.snapshot.observed_at))) return;
  if (live.snapshot?.total !== null && live.snapshot && snapshot.total !== null &&
      (snapshot.total - live.snapshot.total > snapshot.limit || snapshot.total < live.snapshot.total)) live.gap = true;
  if (live.paused && live.pauseTotal !== null && snapshot.total - live.pauseTotal > snapshot.limit) live.gap = true;
  live.snapshot = snapshot;
  if (!live.paused) live.displayed = snapshot.items.filter((event) => !live.cleared.has(event.event_id));
  if (state.socket?.readyState === WebSocket.OPEN) {
    $("live-connection").textContent = snapshot.status === "available" ? "Live connection · periodic event updates" :
      snapshot.status === "connecting" ? "Live connection · awaiting event source" : "Live connection · event source unavailable";
  }
  renderLiveEvents();
}

function renderLiveEvents() {
  const snapshot = live.snapshot;
  const level = $("event-level").value;
  const source = $("event-source").value.trim();
  const eventType = $("event-type").value.trim();
  const search = $("event-search").value.trim().toLowerCase();
  const matches = live.displayed.filter((event) => (!level || event.level === level) &&
    (!source || event.source === source) && (!eventType || event.event_type === eventType) &&
    (!search || [event.event_id, event.source, event.event_type, event.logger, JSON.stringify(event.details)].join(" ").toLowerCase().includes(search)));
  const rows = matches.map((event) => {
    const row = node("tr");
    const levelCell = node("td"); levelCell.append(node("span", event.level, `pill log-${event.level.toLowerCase()}`));
    const description = node("td");
    const open = node("button", event.event_type, "incident-link"); open.type = "button";
    open.addEventListener("click", () => showLiveEvent(event));
    description.append(open, node("span", event.event_id, "pattern-label"));
    const details = Object.entries(event.details).map(([key, value]) => `${key}: ${value}`).join(" · ");
    row.append(node("td", time(event.received_at)), levelCell, node("td", event.source), description,
      node("td", details ? details.slice(0, 140) + (details.length > 140 ? "…" : "") : "No selected details"));
    return row;
  });
  $("live-rows").replaceChildren(...rows);
  const ready = snapshot?.total !== null && snapshot?.total !== undefined;
  $("live-count").textContent = ready ? String(live.displayed.length) : "—";
  $("live-matching").textContent = ready ? String(matches.length) : "—";
  $("live-mode").textContent = snapshot?.status === "unavailable" ? "Unavailable" : live.paused ? "Paused" :
    ready && state.socket?.readyState !== WebSocket.OPEN ? "Disconnected" : ready ? "Live" : "Connecting";
  $("live-cadence").textContent = snapshot ? `Source checked every ${snapshot.poll_seconds} ${snapshot.poll_seconds === 1 ? "second" : "seconds"}` : "Awaiting event source";
  $("live-last-refresh").textContent = snapshot?.last_success_at ? `Last observed ${time(snapshot.last_success_at)}` : "Awaiting first successful observation";
  $("live-window").textContent = ready ? `${matches.length} matching · ${live.displayed.length} in view · ${snapshot.total} stored events` : "No event data loaded";
  const visibleIDs = new Set(live.displayed.map((event) => event.event_id));
  const pending = snapshot?.items.filter((event) => !visibleIDs.has(event.event_id) && !live.cleared.has(event.event_id)).length || 0;
  $("live-pending").textContent = live.paused ? `${pending} new in current window · resume to display` : "Newest arrivals first";
  $("live-gap").hidden = !(snapshot?.gap_possible || live.gap);
  const notice = $("live-notice");
  notice.className = snapshot?.status === "unavailable" ? "notice error" : "notice";
  if (snapshot?.status === "unavailable") {
    notice.textContent = ready ? "Event source unavailable. Showing stale data from the last successful observation." : "Event source unavailable. No event data loaded.";
  } else if (live.paused) {
    notice.textContent = "Display paused. Updates continue in the background; resume to show the current window.";
  } else if (!ready) {
    notice.textContent = "Loading recent events…";
  } else if (!live.displayed.length) {
    notice.textContent = live.clearedView ? "View cleared. Waiting for new events." : "No events received yet. Waiting for incoming signals.";
  } else {
    notice.textContent = matches.length ? "Selected fields only. Open an event to inspect its details." : "No events match the current filters.";
  }
}

async function refreshLiveFeed() {
  const request = ++live.request;
  try {
    const snapshot = await api("/api/live-feed");
    if (state.active && request === live.request) renderLiveSnapshot(snapshot);
  } catch (error) {
    if (state.active && request === live.request) {
      $("live-notice").textContent = `${error.message} Displayed data may be stale.`;
      $("live-notice").className = "notice error";
    }
  }
}

function showLiveEvent(event) {
  resetInvestigation();
  state.detailRequest++; state.detailController?.abort();
  $("detail-kind").textContent = "EVENT INSPECTION";
  $("detail-title").textContent = event.event_type;
  $("detail-notice").textContent = "Selected event fields. Raw messages and tool output are omitted.";
  const facts = node("dl");
  for (const [label, value] of [["Event ID", event.event_id], ["Log level", event.level], ["Source", event.source],
    ["Logger", event.logger], ["Event time", time(event.timestamp)], ["Received", time(event.received_at)]]) {
    facts.append(node("dt", label), node("dd", value));
  }
  const details = node("pre", JSON.stringify(event.details, null, 2), "event-details");
  $("detail-content").replaceChildren(facts, node("h3", "Selected details"), details);
  $("incident-dialog").showModal();
}

$("live-refresh").addEventListener("click", refreshLiveFeed);
$("live-pause").addEventListener("click", () => {
  live.paused = !live.paused;
  live.pauseTotal = live.snapshot?.total ?? null;
  if (!live.paused && live.snapshot) live.displayed = live.snapshot.items.filter((event) => !live.cleared.has(event.event_id));
  $("live-pause").textContent = live.paused ? "Resume display" : "Pause display";
  $("live-pause").setAttribute("aria-pressed", String(live.paused));
  renderLiveEvents();
});
$("live-clear").addEventListener("click", () => {
  live.cleared = new Set(live.snapshot?.items.map((event) => event.event_id) || []);
  live.displayed = []; live.clearedView = true; live.pauseTotal = live.snapshot?.total ?? null;
  renderLiveEvents();
});
$("live-filters").addEventListener("submit", (event) => { event.preventDefault(); renderLiveEvents(); });
$("live-filters").addEventListener("input", renderLiveEvents);
$("live-filters").addEventListener("reset", () => {
  for (const id of ["event-level", "event-source", "event-type", "event-search"]) $(id).value = "";
  renderLiveEvents();
});
const auditLog = { offset: 0, limit: 20, total: 0, filters: {}, boundary: null, request: 0,
  controller: null, lastLoaded: null, loadedOffset: 0, pageText: "", busy: false };
function resetAuditLog() {
  auditLog.request++; auditLog.controller?.abort();
  auditLog.offset = 0; auditLog.total = 0; auditLog.boundary = null;
  auditLog.lastLoaded = null; auditLog.busy = false; auditLog.pageText = ""; auditLog.loadedOffset = 0;
  $("audit-rows").replaceChildren();
  for (const id of ["audit-total", "audit-matching"]) $(id).textContent = "—";
  $("audit-integrity").textContent = "Not checked";
  $("audit-source").textContent = "Awaiting controller journal";
  $("audit-observed").textContent = "No successful read yet";
  $("audit-integrity-caption").textContent = "No integrity result available";
  $("audit-page").textContent = "No audit data loaded";
  $("audit-checkpoint").textContent = "Journal head: not read";
  $("audit-notice").textContent = "Sign in to read the controller journal.";
  $("audit-refresh").disabled = false;
  $("audit-previous").disabled = true; $("audit-next").disabled = true;
}
function showAuditEntry(entry) {
  resetInvestigation(); state.detailRequest++; state.detailController?.abort();
  $("detail-kind").textContent = "AUDIT EVENT";
  $("detail-title").textContent = `#${entry.sequence} · ${entry.event.replaceAll("_", " ")}`;
  $("detail-notice").textContent = "Selected fields from the last successful journal read. Hashes describe the full original record; filtered rows need not be adjacent in the chain.";
  const facts = node("dl");
  for (const [label, value] of [["Sequence", entry.sequence], ["Recorded", time(entry.at)], ["Event", entry.event],
    ["Action ID", entry.action_id], ["Action type", entry.type], ["Actor", entry.actor], ["Initiated by", entry.initiated_by],
    ["Incident ID", entry.incident_id], ["Outcome", entry.status], ["Attempt ID", entry.attempt_id],
    ["Proposal hash", entry.proposal_hash], ["Previous entry hash", entry.previous_hash], ["Entry hash", entry.entry_hash]]) {
    facts.append(node("dt", label), node("dd", value ?? "Not recorded"));
  }
  $("detail-content").replaceChildren(facts, node("h3", "Selected details"),
    node("pre", JSON.stringify(entry.details, null, 2), "event-details"));
  if (!$("incident-dialog").open) $("incident-dialog").showModal();
}
async function loadAuditLog() {
  let loaded = false;
  const request = ++auditLog.request;
  auditLog.controller?.abort(); auditLog.controller = new AbortController(); auditLog.busy = true;
  $("audit-previous").disabled = true; $("audit-next").disabled = true;
  $("audit-notice").className = "notice";
  $("audit-notice").textContent = auditLog.lastLoaded ? "Refreshing audit entries…" : "Loading audit entries…";
  const params = new URLSearchParams({ ...auditLog.filters, limit: auditLog.limit, offset: auditLog.offset });
  if (auditLog.boundary !== null) params.set("through_sequence", auditLog.boundary);
  try {
    const page = await api(`/api/audit-log?${params}`, { signal: auditLog.controller.signal });
    if (!state.active || request !== auditLog.request) return;
    if (auditLog.offset > 0 && auditLog.offset >= page.total) {
      auditLog.offset = Math.max(0, Math.floor((page.total - 1) / auditLog.limit) * auditLog.limit);
      return loadAuditLog();
    }
    loaded = true;
    auditLog.total = page.total; auditLog.boundary = page.through_sequence;
    auditLog.lastLoaded = page.observed_at; auditLog.loadedOffset = page.offset;
    $("audit-rows").replaceChildren(...page.items.map((entry) => {
      const row = node("tr");
      const recorded = node("td", `#${entry.sequence}`); recorded.append(node("span", time(entry.at), "pattern-label"));
      const event = node("td"); const open = node("button", entry.event.replaceAll("_", " "), "incident-link");
      open.type = "button"; open.addEventListener("click", () => showAuditEntry(entry));
      event.append(open, node("span", `${entry.type || "Action"} · ${entry.action_id}`, "pattern-label"));
      const actor = node("td", entry.actor); if (entry.initiated_by) actor.append(node("span", `Initiated by ${entry.initiated_by}`, "pattern-label"));
      const outcome = node("td"); outcome.append(node("span", entry.status ? entry.status.replaceAll("_", " ") : "Not recorded", "pill neutral"));
      row.append(recorded, event, actor, node("td", entry.incident_id || "Not recorded"), outcome);
      return row;
    }));
    $("audit-total").textContent = String(page.journal_total);
    $("audit-matching").textContent = String(page.total);
    $("audit-integrity").textContent = "Consistent";
    $("audit-integrity-caption").textContent = "Local event chain only · no external anchor";
    $("audit-source").textContent = "Controller journal available · manual refresh";
    $("audit-checkpoint").textContent = `Snapshot head: ${page.head}`;
    $("audit-observed").textContent = `Last read ${time(page.observed_at)}`;
    auditLog.pageText = page.total ? `${page.offset + 1}–${page.offset + page.items.length} of ${page.total} matching entries · through sequence ${page.through_sequence}` : "0 matching entries";
    $("audit-page").textContent = auditLog.pageText;
    $("audit-notice").textContent = page.total ? "Newest sequence first. Open an event to inspect its selected fields." : page.journal_total ? "No audit entries match these filters." : "The controller journal has no recorded events yet.";
  } catch (error) {
    if (!state.active || request !== auditLog.request || error.name === "AbortError") return;
    $("audit-source").textContent = "Controller journal unavailable";
    $("audit-integrity").textContent = "Not confirmed";
    $("audit-integrity-caption").textContent = "Current integrity could not be confirmed";
    $("audit-notice").className = "notice error";
    $("audit-notice").textContent = `${error.message}.${auditLog.lastLoaded ? ` Showing stale rows from ${time(auditLog.lastLoaded)}; they may belong to previous filters or a previous page.` : " No audit data loaded."}`;
    $("audit-page").textContent = auditLog.lastLoaded ? `${auditLog.pageText} · stale` : "No audit data loaded";
    auditLog.offset = auditLog.loadedOffset;
  } finally {
    if (request === auditLog.request && state.active) {
      auditLog.busy = false;
      $("audit-previous").disabled = !loaded || auditLog.offset === 0;
      $("audit-next").disabled = !loaded || !auditLog.lastLoaded || auditLog.offset + auditLog.limit >= auditLog.total;
    }
  }
}
$("audit-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  const filters = {};
  for (const [id, key] of [["audit-event", "event"], ["audit-actor", "actor"], ["audit-action", "action_id"], ["audit-incident", "incident_id"], ["audit-status", "status"]]) {
    if ($(id).value.trim()) filters[key] = $(id).value.trim();
  }
  for (const [id, key] of [["audit-since", "since"], ["audit-until", "until"]]) {
    if ($(id).value) filters[key] = new Date(`${$(id).value}Z`).toISOString();
  }
  if (filters.since && filters.until && filters.since > filters.until) {
    $("audit-notice").textContent = "Start time must be before end time. Filters were not applied."; return;
  }
  auditLog.filters = filters; auditLog.offset = 0; auditLog.boundary = null;
  auditLog.limit = Number($("audit-limit").value); loadAuditLog();
});
$("audit-filters").addEventListener("reset", () => {
  auditLog.filters = {}; auditLog.offset = 0; auditLog.limit = 20; auditLog.boundary = null; loadAuditLog();
});
$("audit-refresh").addEventListener("click", () => { auditLog.boundary = null; auditLog.offset = 0; loadAuditLog(); });
$("audit-previous").addEventListener("click", () => { auditLog.offset = Math.max(0, auditLog.offset - auditLog.limit); loadAuditLog(); });
$("audit-next").addEventListener("click", () => { auditLog.offset += auditLog.limit; loadAuditLog(); });

(async () => {
  if (!await loadAccess() || access.mode === "setup") return;
  try { await api("/api/session"); await activate(); } catch {}
})();