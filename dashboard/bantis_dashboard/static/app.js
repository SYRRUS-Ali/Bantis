"use strict";

const $ = (id) => document.getElementById(id);
const state = { offset: 0, limit: 20, total: 0, filters: {}, socket: null, retry: null,
  delay: 1000, active: false, listRequest: 0, detailRequest: 0, lastList: null, snapshot: null,
  listController: null, detailController: null, lastSequence: -1, listBusy: false };

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
  stopSocket();
  state.listRequest++; state.detailRequest++;
  state.listController?.abort(); state.detailController?.abort();
  state.lastList = null; state.snapshot = null; state.offset = 0; state.total = 0;
  state.lastSequence = -1;
  state.listBusy = false;
  $("incident-rows").replaceChildren(); $("detail-content").replaceChildren();
  $("incident-dialog").close();
  $("total-incidents").textContent = "—";
  $("workspace").hidden = true; $("login-screen").hidden = false;
  $("access-token").value = "";
  $("access-token").focus();
}
async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  if (response.status === 401 && !(path === "/api/session" && options.method === "POST")) {
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
  $("connection-label").textContent = "Connecting to live updates…";
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  state.socket = socket;
  socket.onopen = () => { state.delay = 1000; $("connection-label").textContent = "Live connection · awaiting observation"; };
  socket.onmessage = (event) => {
    let snapshot;
    try { snapshot = JSON.parse(event.data); } catch { return; }
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
    $("connection-label").textContent = "Live connection lost · displayed data may be stale · reconnecting…";
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
  loadIncidents(); connect();
  try { renderSnapshot(await api("/api/status")); } catch {}
}
async function showIncident(id) {
  const request = ++state.detailRequest;
  state.detailController?.abort(); state.detailController = new AbortController();
  const options = { signal: state.detailController.signal };
  $("detail-content").replaceChildren(); $("detail-title").textContent = "Incident detail";
  $("detail-notice").textContent = "Loading incident and evidence…";
  if (!$("incident-dialog").open) $("incident-dialog").showModal();
  try {
    const incident = await api(`/api/incidents/${encodeURIComponent(id)}`, options);
    if (request !== state.detailRequest || !state.active) return;
    $("detail-title").textContent = incident.summary;
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
    $("detail-notice").textContent = "Selected evidence fields are shown. Raw messages and tool output are omitted. Copilot analysis is not connected.";
  } catch (error) {
    if (request === state.detailRequest && error.name !== "AbortError" && state.active) $("detail-notice").textContent = error.message;
  }
}
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button"); button.disabled = true;
  const token = $("access-token").value; $("access-token").value = "";
  try {
    await api("/api/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
    await activate();
  } catch (error) { $("login-error").textContent = error.message; }
  finally { button.disabled = false; }
});
$("sign-out").addEventListener("click", async () => {
  try { await api("/api/session", { method: "DELETE" }); signedOut(); }
  catch (error) { if (state.active) $("connection-label").textContent = `Sign out failed: ${error.message}`; }
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
$("incident-dialog").addEventListener("close", () => { state.detailRequest++; state.detailController?.abort(); });
(async () => { try { await api("/api/session"); await activate(); } catch {} })();