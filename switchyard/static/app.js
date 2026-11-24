"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const ui = {
    reload: byId("reload"), status: byId("fleet-status"), error: byId("fleet-error"),
    yard: byId("yard"), yardNote: byId("yard-note"),
    hosts: byId("host-list"), hostSearch: byId("host-search"), hostCount: byId("host-count"),
    workloads: byId("workload-list"), definedSearch: byId("defined-search"), workloadSearch: byId("workload-search"),
    lifecycle: byId("lifecycle-filter"), freshness: byId("freshness-filter"), workloadCount: byId("workload-count"),
    discovery: byId("discovery-list"), discoveryCount: byId("discovery-count"), backends: byId("backend-list"),
    backend: byId("backend-filter"), scope: byId("scope-filter"), grouping: byId("grouping-filter"),
    artifacts: byId("artifact-list"), artifactCount: byId("artifact-count"),
    form: byId("proposal-form"), workload: byId("workload-select"), target: byId("target-select"),
    workloadContext: byId("workload-context"), targetContext: byId("target-context"), reviewContext: byId("review-context"),
    route: byId("route-diagram"), prepare: byId("create-proposal"), proposal: byId("proposal-result"),
    proposalStatus: byId("proposal-status"), proposalError: byId("proposal-error"),
  };
  const op = {
    panel: byId("managed-operations"), workload: byId("operation-workload"), action: byId("operation-action"), target: byId("operation-target"),
    form: byId("operation-form"), plan: byId("operation-plan"), approval: byId("approve-operation"),
    execute: byId("execute-operation"), requestId: byId("operation-request-id"),
    status: byId("operation-status"), error: byId("operation-error"),
    shellPanel: byId("shell-panel"), shellForm: byId("shell-form"), shellHost: byId("shell-host"), script: byId("shell-script"),
    timeout: byId("shell-timeout"), shellId: byId("shell-request-id"), extra: byId("shell-extra-hosts"),
    shellStatus: byId("shell-status"), shellError: byId("shell-error"), output: byId("shell-output"),
    receipts: byId("operation-receipts"),
    inspect: byId("inspect-workload"), inspection: byId("operation-inspection"),
  };
  let operationPlan = null;
  let operationPending = false;
  let operationAttempted = false;
  let operationsOpen = false;
  let policySignature = "";
  const receiptDetails = new Map();
  const keys = {
    hosts: byId("fleet-key-hosts"), action: byId("fleet-key-action"), plan: byId("fleet-key-plan"),
    approval: byId("approve-fleet-keys"), requestId: byId("fleet-key-request-id"),
    status: byId("fleet-key-status"), error: byId("fleet-key-error"),
  };
  const editor = {
    panel: byId("definition-editor"), form: byId("definition-form"), id: byId("definition-id"),
    name: byId("definition-name"), purpose: byId("definition-purpose"), supporting: byId("definition-supporting"),
    review: byId("definition-review"), save: byId("save-definition"),
    status: byId("definition-status"), error: byId("definition-error"),
  };
  let keyPlan = null;
  let keyPending = false;
  let keyAttempted = false;
  let keyHostSignature = "";
  let keyPlanRevision = null;
  let definitionDraft = null;
  let definitionPending = false;
  let definitionReviewed = null;
  let definitionReviewFleetRevision = null;
  const hostEditor = {
    panel: byId("host-editor"), form: byId("host-form"), status: byId("host-editor-status"), error: byId("host-editor-error"),
    connection: byId("host-connection"), review: byId("host-review"), save: byId("save-host"),
    pins: byId("host-pins"), scan: byId("host-key-scan"), confirm: byId("confirm-host-key"),
  };
  const hostFields = {
    name: byId("host-name"), platform: byId("host-platform"), architecture: byId("host-architecture"),
    capabilities: byId("host-capabilities"), notes: byId("host-notes"),
    account: byId("host-account"), address: byId("host-address"), port: byId("host-port"),
    expected_hostname: byId("host-expected-hostname"),
  };
  let hostDraft = null;
  let hostReviewed = null;
  let hostScan = null;
  let hostPending = false;
  const paseoEditor = {
    panel: byId("paseo-editor"), form: byId("paseo-form"), listen: byId("paseo-listen"), cli: byId("paseo-cli"),
    review: byId("paseo-review"), save: byId("save-paseo"), status: byId("paseo-status"), error: byId("paseo-error"),
  };
  let agentsData = null;
  let agentsLoading = false;
  let agentsSignature = "";
  let workloadHostFilter = null;
  let paseoDraft = null;
  let paseoReviewed = null;
  let paseoPending = false;
  const tabs = ["workloads", "lan-urls", "hosts", "agents", "playbooks", "access", "migration", "receipts"];
  const opened = new Set();
  const hostErrors = new Map();
  const staleOwners = new WeakMap();
  let fleet = null;
  let receivedAt = 0;
  let request = null;
  let wizardStep = 1;
  let currentPlan = null;
  let proposalSummary = "";
  let cacheReadFailed = false;
  let stream = null;
  let streamGeneration = 0;
  let streamHealthy = false;
  let reconnectTimer = null;
  let reconnectSeconds = 3;
  let pageClosed = false;
  // GET /api/auth/session, or null where the server predates sign-in (404): then the page behaves as before.
  let auth = null;
  let sessionUnknown = false;
  let sessionCheck = null;
  let signedOut = false;
  let signInPending = false;
  let signInReturn = null;
  const access = { enrollments: null, keys: null, signature: "", loading: false, again: false, timer: null, busy: null, confirm: null, target: null, located: null, drafts: new Map() };

  const clock = (value) => new Date(value).toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" });
  function setStream(aspect, label, detail) {
    byId("stream-lamp").className = `lamp lamp-${aspect}`;
    byId("stream-text").textContent = label;
    byId("stream-status").title = detail;
  }
  function pauseStream() {
    streamGeneration += 1;
    if (stream) stream.close();
    stream = null;
    window.clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  function startStream() {
    if (pageClosed || signedOut || request || stream || reconnectTimer) return;
    if (!window.EventSource) {
      setStream("dark", "No live updates", "This browser cannot stream updates. Refresh reads the cache.");
      return;
    }
    const generation = ++streamGeneration;
    const source = new EventSource("/api/events");
    stream = source;
    source.addEventListener("fleet", (event) => {
      if (generation !== streamGeneration || request || pageClosed) return;
      try {
        acceptFleet(JSON.parse(event.data));
        streamHealthy = true;
        reconnectSeconds = 3;
        setStream("run", `Live, ${clock(receivedAt)}`, "Cached snapshots arrive as they change. This connection is not a host health check.");
        updateControls();
      } catch (cause) {
        setStream("fail", "Update rejected", "A live update did not match the expected shape. The last good data stays on screen; Refresh re-reads the cache.");
      }
    });
    source.onerror = () => {
      if (generation !== streamGeneration || pageClosed) return;
      pauseStream();
      // The desk ends every stream after a minute. Reconnect once without comment;
      // only a reconnect that also fails is worth the operator's attention.
      const routine = streamHealthy;
      streamHealthy = false;
      const delay = routine ? 1 : reconnectSeconds;
      if (!routine) {
        setStream("transit", `Updates paused, retrying in ${delay}s`, "Showing the last data received. Reconnecting never contacts a host.");
        reconnectSeconds = Math.min(30, reconnectSeconds * 2);
        // A stream refused for want of a session looks like any other failure here; ask the server which it was.
        recheckSession();
      }
      reconnectTimer = window.setTimeout(() => { reconnectTimer = null; startStream(); }, delay * 1000);
    };
  }

  function node(tag, value, className) {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = String(value);
    if (className) element.className = className;
    return element;
  }
  function group(tag, className, ...children) {
    const element = node(tag, undefined, className);
    element.append(...children.filter((child) => child !== null && child !== undefined && child !== false));
    return element;
  }
  const text = (value, fallback = "Unknown") => typeof value === "string" && value.trim() ? value : fallback;
  const array = (value) => Array.isArray(value) ? value : [];
  const strings = (value) => array(value).filter((item) => typeof item === "string");
  const number = (value) => typeof value === "number" && Number.isFinite(value);
  const sentence = (value) => value.charAt(0).toUpperCase() + value.slice(1).replaceAll("-", " ");
  const empty = (value) => node("p", value, "empty-state");
  function error(element, value) {
    element.textContent = value;
    element.hidden = !value;
  }
  function bytes(value) {
    if (!number(value) || value < 0) return "Unknown";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let size = value;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return `${size.toLocaleString(undefined, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
  }
  const percent = (value, digits = 1) => number(value) ? `${value.toLocaleString(undefined, { maximumFractionDigits: digits })}%` : "Unknown";
  const timestamp = (value) => {
    const date = new Date(value);
    return value && Number.isFinite(date.getTime()) ? date.toLocaleString() : "Never";
  };
  function ageSeconds(observedAt) {
    const time = Date.parse(observedAt);
    return Number.isFinite(time) ? Math.max(0, (Date.now() - time) / 1000) : null;
  }
  function ageLabel(age) {
    if (!number(age)) return "age unknown";
    if (age < 60) return "under 1 min ago";
    if (age < 3600) return `${Math.floor(age / 60)} min ago`;
    if (age < 86400) return `${Math.floor(age / 3600)} hr ago`;
    const days = Math.floor(age / 86400);
    return `${days} ${days === 1 ? "day" : "days"} ago`;
  }
  function freshness(observedAt, fallback, ttl = 120) {
    const age = ageSeconds(observedAt);
    return age === null ? text(fallback, "never") : age < (number(ttl) && ttl > 0 ? ttl : 120) ? "fresh" : "stale";
  }
  // `owner` dims with its evidence: a lamp beside stale evidence must not look current.
  function ageNode(observedAt, fallback, ttl = 120, owner = null) {
    const label = node("span", undefined, "freshness");
    if (observedAt) label.dataset.observedAt = observedAt;
    label.dataset.fallback = text(fallback, "never");
    label.dataset.ttl = String(number(ttl) && ttl > 0 ? ttl : 120);
    if (owner) staleOwners.set(label, owner);
    updateAge(label);
    return label;
  }
  function updateAge(label) {
    const value = freshness(label.dataset.observedAt, label.dataset.fallback, Number(label.dataset.ttl));
    const age = ageLabel(ageSeconds(label.dataset.observedAt));
    label.textContent = value === "never" ? "Never checked" : value === "unknown" ? "Time unknown"
      : value === "fresh" ? sentence(age) : `${label.dataset.retained === "true" ? "Stale, retained" : "Stale"}, ${age}`;
    label.classList.toggle("caution", value !== "fresh");
    label.title = timestamp(label.dataset.observedAt);
    staleOwners.get(label)?.classList.toggle("is-stale", value !== "fresh");
  }
  const ASPECTS = { running: "run", idle: "idle", starting: "transit", stopping: "transit", stopped: "halt", completed: "done", failed: "fail" };
  // A lamp is decorative next to its state word; the tooltip names it where the word is not adjacent.
  const ASPECT_LABELS = { run: "Running", idle: "Idle", transit: "Starting or stopping", halt: "Stopped", done: "Completed", fail: "Failed", dark: "Unknown" };
  function lamp(aspect, label) {
    const mark = node("span", undefined, `lamp lamp-${aspect}`);
    mark.setAttribute("aria-hidden", "true");
    if (label) mark.title = label;
    return mark;
  }
  const lifecycleLamp = (lifecycle) => lamp(ASPECTS[lifecycle] || "dark", ASPECT_LABELS[ASPECTS[lifecycle] || "dark"]);
  function flag() {
    const mark = node("span", undefined, "flag-mark");
    mark.setAttribute("aria-hidden", "true");
    return mark;
  }
  function metadata(entries) {
    const result = node("dl", undefined, "metadata");
    entries.forEach(([label, value]) => result.append(node("dt", label), value instanceof Node ? group("dd", "", value) : node("dd", value)));
    return result;
  }
  function list(values, fallback) {
    if (!values.length) return empty(fallback);
    const result = node("ul", undefined, "text-list");
    values.forEach((value) => result.append(node("li", value)));
    return result;
  }
  function table(headers, rows, caption) {
    const result = node("table", undefined, "data-table");
    if (caption) result.append(node("caption", caption));
    const head = node("tr");
    headers.forEach((label) => { const cell = node("th", label); cell.scope = "col"; head.append(cell); });
    const body = node("tbody");
    rows.forEach((cells) => {
      const row = node("tr");
      cells.forEach((value, index) => {
        const cell = node(index ? "td" : "th");
        if (!index) cell.scope = "row";
        cell.append(value instanceof Node ? value : String(value));
        row.append(cell);
      });
      body.append(row);
    });
    result.append(group("thead", "", head), body);
    return result;
  }
  function disclosure(key, title, content, className = "record") {
    const details = node("details", undefined, className);
    details.dataset.detailKey = key;
    details.open = opened.has(key);
    const summary = node("summary");
    summary.dataset.focusKey = `summary:${key}`;
    summary.append(title);
    details.append(summary, content);
    details.addEventListener("toggle", () => {
      if (!details.isConnected) return;
      if (details.open) opened.add(key); else opened.delete(key);
    });
    return details;
  }
  function rememberDetails(root) {
    root.querySelectorAll("details[data-detail-key]").forEach((details) => {
      if (details.open) opened.add(details.dataset.detailKey); else opened.delete(details.dataset.detailKey);
    });
  }
  // Lists are rebuilt on every cached update. Keep disclosures open and keyboard focus where it was.
  function rerender(root, render) {
    const active = root.contains(document.activeElement) ? document.activeElement.closest("[data-focus-key]")?.dataset.focusKey : null;
    rememberDetails(root);
    render();
    if (active) Array.from(root.querySelectorAll("[data-focus-key]")).find((item) => item.dataset.focusKey === active)?.focus({ preventScroll: true });
  }
  function locate(element) {
    if (!element) return;
    element.scrollIntoView({ block: "center", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    element.classList.remove("is-located");
    void element.offsetWidth;
    element.classList.add("is-located");
    (element.querySelector("summary") || element).focus({ preventScroll: true });
  }
  function resourceAge(snapshot, scope) {
    const status = fleet?.hosts.find((host) => host.id === snapshot?.host_id)?.resource_status?.[scope];
    const label = ageNode(status?.observed_at || snapshot?.resource_observed_at?.[scope], status?.freshness || "unknown", status?.freshness_ttl_seconds);
    label.dataset.retained = String(Date.parse(snapshot?.resource_observed_at?.[scope]) < Date.parse(snapshot?.observed_at));
    updateAge(label);
    return label;
  }
  function resourceHeading(snapshot, title, scope) {
    const heading = node("div", undefined, "resource-heading");
    heading.append(node("h4", title), resourceAge(snapshot, scope));
    return heading;
  }
  function declaredCapabilities(host) { return strings(host.declared_capabilities); }
  function canObserve(host) { return host.collection_enabled === true && host.capabilities?.observe === true; }
  function evidence(key, value, label = "Raw data (JSON)") {
    const content = node("pre", JSON.stringify(value, null, 2), "evidence");
    content.tabIndex = 0;
    return disclosure(key, label, content);
  }
  // Hosts are shown by what the machine calls itself (`hostname`), as the operator asked; the server falls
  // back to the registry ID for devices that cannot be asked. The friendly name stays as secondary text.
  function hostLabel(host) { return host ? text(host.hostname, text(host.id, text(host.host_id))) : ""; }
  function hostName(id) {
    const host = fleet && fleet.hosts.find((item) => item.id === id);
    return host ? hostLabel(host) : text(id);
  }
  function sourceId(workload) { return workload && (workload.host_id || workload.device_id); }
  function selectedWorkload() {
    return fleet && fleet.workloads.find((item) => item.id === ui.workload.value);
  }
  function selectedTarget() { return fleet && fleet.hosts.find((item) => item.id === ui.target.value); }
  function matches(item, query) { return !query || JSON.stringify(item).toLocaleLowerCase().includes(query); }

  async function api(path, body, timeoutMs = 35000) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const options = { signal: controller.signal, cache: "no-store", headers: { Accept: "application/json" } };
      if (body !== undefined) {
        options.method = "POST";
        options.headers["Content-Type"] = "application/json";
        // A signed-in session proves each change with its CSRF token; the cookie alone is not enough.
        if (typeof auth?.csrf_token === "string" && auth.csrf_token) options.headers["X-Switchyard-CSRF"] = auth.csrf_token;
        options.body = JSON.stringify(body);
      }
      const response = await fetch(path, options);
      // On the loopback desk an ended operator session falls back to "local" and gets 403, not 401; a stale CSRF token is 403 too.
      if ((response.status === 401 || (response.status === 403 && isOperator())) && !path.startsWith("/api/auth/")) recheckSession();
      if (response.status === 204) return {};
      let data;
      try { data = await response.json(); }
      catch (cause) {
        if (cause.name === "AbortError") throw cause;
        const failure = new Error(`Non-JSON response (HTTP ${response.status}).`);
        failure.status = response.status;
        throw failure;
      }
      if (!response.ok) {
        const failure = new Error(text(data && data.error, `Request failed (HTTP ${response.status}).`));
        failure.status = response.status;
        failure.retryAfter = response.headers.get("Retry-After") ?? data?.retry_after_seconds ?? null;
        throw failure;
      }
      if (!data || typeof data !== "object") throw new Error("Unexpected API response.");
      return data;
    } catch (cause) {
      if (cause.name === "AbortError") throw new Error(`Request timed out. Its outcome is unknown and it was not retried. ${path.startsWith("/api/operations") || path.startsWith("/api/fleet-keys") ? "Check the audit log before another execution."
        : path.startsWith("/api/ansible") ? "Read the Runs list and the Audit log before another plan or apply."
        : path.startsWith("/api/lan-urls") ? "Reload LAN URLs before anything else: an unfinished change shows at the top, and applying again with the same request ID returns the first result."
        : path.startsWith("/api/enrollments") || path.startsWith("/api/keys") ? "Reload requests and keys to see whether it took effect." : "Read current definitions or refresh before another save."}`);
      if (cause instanceof TypeError) throw new Error("Could not reach the API. The request was not retried.");
      throw cause;
    } finally { window.clearTimeout(timeout); }
  }
  function normalizeFleet(data) {
    const records = (items) => Array.isArray(items) && items.every((item) => item && typeof item === "object" && !Array.isArray(item));
    if (!["observe-and-propose", "scoped-operations"].includes(data.mode) || ![data.hosts, data.workloads, data.resources, data.environments, data.backends].every(records)) throw new Error("Fleet response did not match the defined-workload contract.");
    if (![data.artifacts ?? [], data.groups ?? []].every(records) || !data.monitoring || typeof data.monitoring !== "object") throw new Error("Fleet inventory did not match the cached observation contract.");
    return { ...data, artifacts: data.artifacts ?? [], groups: data.groups ?? [] };
  }
  function acceptFleet(data) {
    const scroll = [window.scrollX, window.scrollY];
    fleet = normalizeFleet(data);
    // A read-only listener refuses every action, so the page does not offer them there.
    document.documentElement.classList.toggle("is-view-only", fleet.read_only_view === true);
    if (fleet.read_only_view === true) {
      commonsHandoff.panel.hidden = true;
      commonsHandoff.input.value = "";
    }
    receivedAt = Date.now();
    cacheReadFailed = false;
    hostErrors.clear();
    fillFilters();
    renderOperations();
    renderYard();
    renderHosts();
    renderWorkloads();
    renderDiscovery();
    renderMonitoring();
    renderArtifacts();
    renderBackends();
    fillSelections();
    renderContexts();
    renderFleetKeys();
    definitionControls();
    hostEditorControls();
    paseoEditorControls();
    loadAgents();
    sessionControls();
    loadAccess();
    // Host names may have changed; the first fleet read also loads the Playbooks tab if it is open.
    if (currentTab === "playbooks" && !pb.list) loadPlaybooks();
    else if (pb.list) renderRuns();
    // LAN URLs are read when their tab is shown; workload names in an open list and editor follow the fleet.
    if (currentTab === "lan-urls" && !lan.data) loadLanUrls();
    else if (lan.data) renderLanUrls();
    window.scrollTo(...scroll);
    if (currentPlan) ui.proposalStatus.textContent = `${proposalSummary} The cache has updated since; run it again to use the latest data.`;
  }
  async function loadFleet(announce = false) {
    if (request || signedOut) return;
    pauseStream();
    request = { kind: "cache" };
    updateControls();
    error(ui.error, "");
    if (announce) ui.status.textContent = "Reading the cache. No hosts are contacted.";
    try {
      acceptFleet(await api("/api/fleet"));
      if (announce) ui.status.textContent = `Cache read ${clock(receivedAt)}. No hosts were contacted.`;
    } catch (cause) {
      cacheReadFailed = true;
      error(ui.error, cause.message);
      ui.status.textContent = fleet ? "Refresh failed. Showing the last data received. Refresh to try again." : "Could not load data from the server. Refresh to try again.";
      if (fleet) renderHosts();
      else {
        ui.yard.replaceChildren(empty("No data loaded."));
        ui.hosts.replaceChildren(empty("No data loaded."));
        ui.workloads.replaceChildren(empty("No data loaded."));
      }
    } finally { request = null; updateControls(); startStream(); }
  }
  function cooldown(host) {
    return Math.max(0, Math.ceil((host.observation?.retry_after_seconds || 0) - (Date.now() - receivedAt) / 1000));
  }
  function updateObserveButton(button, host) {
    const remaining = cooldown(host);
    const collecting = request?.kind === "observe" && request.hostId === host.id;
    const serverCollecting = host.observation?.last_attempt?.status === "collecting";
    const unresolved = hostErrors.has(host.id);
    button.disabled = !canObserve(host) || Boolean(request) || remaining > 0 || serverCollecting || unresolved;
    button.textContent = collecting || serverCollecting ? "Checking…" : unresolved ? "Refresh to see result" : remaining > 0 ? `Check in ${remaining}s` : "Check now";
  }
  async function observeHost(hostId) {
    const host = fleet?.hosts.find((item) => item.id === hostId);
    if (request || !host || !canObserve(host) || hostErrors.has(hostId) || cooldown(host) || host.observation?.last_attempt?.status === "collecting") return;
    pauseStream();
    request = { kind: "observe", hostId };
    hostErrors.delete(hostId);
    updateControls();
    error(ui.error, "");
    ui.status.textContent = `Checking ${hostName(hostId)}. Cached readings stay visible.`;
    try {
      acceptFleet(await api("/api/observations/host", { host_id: hostId }));
      const attempt = fleet.hosts.find((item) => item.id === hostId)?.observation?.last_attempt;
      ui.status.textContent = `${hostName(hostId)}: ${text(attempt?.status, "cache returned")}. ${text(attempt?.message, "See the host's last-checked time and data sources.")}`;
    } catch (cause) {
      hostErrors.set(hostId, cause.message);
      ui.status.textContent = `The check of ${hostName(hostId)} failed. Last-known readings stay visible.`;
      error(ui.error, cause.message);
      renderHosts();
    } finally { request = null; updateControls(); startStream(); }
  }

  // --- Yard diagram: one track per host, one car per defined workload. ---
  function yardCar(workload) {
    const car = node("button", undefined, "car");
    car.type = "button";
    car.dataset.focusKey = `car:${workload.id}`;
    car.title = "Show in the list below";
    car.append(lifecycleLamp(workload.lifecycle), node("span", text(workload.name, workload.id), "car-name"),
      node("span", `, ${text(workload.lifecycle)}, `, "visually-hidden"));
    const age = ageNode(workload.observed_at, workload.freshness, workload.freshness_ttl_seconds, car);
    age.classList.add("visually-hidden");
    car.append(age);
    if (managedWorkload(workload.id)) car.append(flag(), node("span", ", managed", "visually-hidden"));
    car.addEventListener("click", () => showWorkload(workload.id));
    return car;
  }
  function yardTrack(id, host, workloads, index) {
    const snapshot = host?.observation?.snapshot;
    const track = node("div", undefined, `track${snapshot ? "" : " is-dark"}`);
    track.setAttribute("role", "listitem");
    track.style.setProperty("--i", String(index));
    const label = node(host ? "button" : "span", host ? hostLabel(host) : text(id), "track-host");
    if (host) {
      label.type = "button";
      label.dataset.focusKey = `track:${id}`;
      label.title = "Show this host";
      label.addEventListener("click", () => showHost(id));
    }
    const line = group("div", "track-line", ...workloads.map(yardCar));
    if (!workloads.length) line.append(node("span", "No defined workloads", "visually-hidden"));
    const end = node("div", undefined, "track-end");
    if (snapshot) {
      const memory = snapshot.memory;
      const used = number(memory?.available_bytes) && number(memory?.total_bytes) && memory.total_bytes > 0 ? (1 - memory.available_bytes / memory.total_bytes) * 100 : null;
      end.append(group("span", "readout", node("span", "CPU", "readout-label"), percent(snapshot.cpu?.utilization_percent, 0)),
        group("span", "readout", node("span", "RAM", "readout-label"), percent(used, 0)),
        ageNode(snapshot.observed_at, host.observation.freshness, host.observation.freshness_ttl_seconds, track));
    } else end.append(node("span", !host ? "Not in catalog" : host.collection_enabled ? "Never checked" : "No collector", "freshness caution"));
    track.append(label, line, end);
    return track;
  }
  function renderYard() {
    if (!fleet) return;
    rerender(ui.yard, () => {
      const cars = new Map();
      fleet.workloads.forEach((workload) => {
        const id = text(sourceId(workload), "unplaced");
        cars.set(id, [...(cars.get(id) || []), workload]);
      });
      const tracks = fleet.hosts.filter((host) => cars.has(host.id) || host.observation?.snapshot).map((host) => [host.id, host]);
      cars.forEach((_, id) => { if (!fleet.hosts.some((host) => host.id === id)) tracks.push([id, null]); });
      const quiet = fleet.hosts.filter((host) => !tracks.some(([id]) => id === host.id));
      ui.yard.replaceChildren(...tracks.map(([id, host], index) => yardTrack(id, host, cars.get(id) || [], index)));
      if (tracks.length) ui.yard.setAttribute("role", "list"); else ui.yard.removeAttribute("role");
      if (!tracks.length) ui.yard.append(empty(fleet.hosts.length ? "No host has reported yet and no workload is defined. Open Hosts and choose Check now." : "The catalog has no hosts."));
      ui.yardNote.replaceChildren();
      if (quiet.length) {
        const more = node("button", `${quiet.length} more ${quiet.length === 1 ? "host" : "hosts"} with no data`, "board-link");
        more.type = "button";
        more.title = quiet.map(hostLabel).join(", ");
        more.addEventListener("click", () => { selectTab("hosts"); locate(ui.hosts.querySelector(".host-row.is-dark")); });
        ui.yardNote.append(more);
      }
    });
  }
  function showWorkload(id) {
    selectTab("workloads");
    // Any roster filter can hide the row a car points at; clear them all rather than land on nothing.
    if (!ui.workloads.querySelector(`[data-workload-row="${CSS.escape(id)}"]`)) {
      ui.definedSearch.value = "";
      byId("defined-state").value = "all";
      workloadHostFilter = null;
      renderWorkloads();
    }
    locate(ui.workloads.querySelector(`[data-workload-row="${CSS.escape(id)}"]`));
  }
  function showHost(id) {
    selectTab("hosts");
    if (!ui.hosts.querySelector(`[data-host-row="${CSS.escape(id)}"]`)) { ui.hostSearch.value = ""; renderHosts(); }
    locate(ui.hosts.querySelector(`[data-host-row="${CSS.escape(id)}"]`));
  }

  // --- Hosts ---
  // `tightAt` marks each bar on its own reading, so one full pool does not colour its neighbours.
  function meterCell(label, value, detail, fractions, tightAt = null) {
    const bars = node("span", undefined, "meter-bars");
    bars.setAttribute("aria-hidden", "true");
    (Array.isArray(fractions) ? fractions : [fractions]).slice(0, 6).forEach((fraction) => {
      const bar = node("span", undefined, "meter");
      if (number(fraction)) {
        const fill = node("span", undefined, "meter-fill");
        fill.style.setProperty("--v", String(Math.min(1, Math.max(0, fraction))));
        bar.append(fill);
        if (number(tightAt) && fraction >= tightAt) bar.classList.add("is-tight");
      } else bar.classList.add("is-unknown");
      bars.append(bar);
    });
    return group("span", "meter-cell", node("span", label, "meter-label"), node("span", value, "meter-value"), bars, node("span", detail, "meter-detail"));
  }
  const measuredPool = (fs) => fs.kind === "persistent" && fs.read_only === false && number(fs.available_bytes) && number(fs.total_bytes) && fs.total_bytes > 0;
  const NETWORK_FILESYSTEMS = new Set(["nfs", "nfs4", "cifs", "smb3", "ceph", "glusterfs", "9p"]);
  function storageInventory(snapshot) {
    const filesystems = array(snapshot?.storage?.filesystems);
    const devices = array(snapshot?.storage?.devices);
    // Real storage only: block-backed or kernel network filesystems. RAM, image, pseudo and non-block FUSE mounts stay in raw evidence.
    const rows = filesystems.filter((fs) => fs.kind === "persistent" || strings(fs.backing_device_ids).length || NETWORK_FILESYSTEMS.has(fs.type));
    const mounted = new Set(filesystems.flatMap((fs) => strings(fs.backing_device_ids)));
    // Boot and EFI partitions are small and full by design: they stay in the storage table but never count
    // as a pool for the summary meter or as the "tightest" one (operator request 2026-11-23).
    const bootOnly = (fs) => strings(fs.mounts).length > 0 && strings(fs.mounts).every((mount) => /^\/(boot|efi)(\/|$)/.test(mount));
    return { rows, pools: rows.filter((fs) => measuredPool(fs) && !bootOnly(fs)), unmounted: devices.filter((device) => !mounted.has(device.id)) };
  }
  function deviceLabel(snapshot, id) {
    const device = array(snapshot?.storage?.devices).find((item) => item.id === id);
    if (!device) return id;
    const media = device.rotational === true ? "HDD" : device.rotational === false ? "SSD" : "media unknown";
    return `${text(device.name, id)} · ${text(device.model, "model unknown")} · ${media}${device.transport ? ` (${device.transport})` : ""} · ${bytes(device.size_bytes)}`;
  }
  function storageTable(snapshot) {
    const { rows, unmounted } = storageInventory(snapshot);
    const lines = rows.map((fs) => {
      const mounts = strings(fs.mounts);
      const measured = number(fs.available_bytes) && number(fs.total_bytes) && fs.total_bytes > 0;
      const free = measured ? `${bytes(fs.available_bytes)} of ${bytes(fs.total_bytes)} (${percent(fs.available_bytes / fs.total_bytes * 100)} free)`
        : strings(fs.backing_device_ids).length ? "Not measured: add the mount to storage_mounts to read it" : "Not measured";
      const cell = node("span", free, measured && fs.available_bytes / fs.total_bytes < 0.1 ? "caution" : undefined);
      return [mounts[0] || text(fs.id), `${text(fs.type)}${fs.read_only === true ? ", read-only" : ""}${mounts.length > 1 ? `, +${mounts.length - 1} views` : ""}`,
        cell, strings(fs.backing_device_ids).map((id) => deviceLabel(snapshot, id)).join("; ") || (NETWORK_FILESYSTEMS.has(fs.type) ? `Network: ${text(fs.source)}` : "Unknown")];
    });
    unmounted.forEach((device) => lines.push(["Not mounted", "No filesystem seen", "Unavailable", deviceLabel(snapshot, device.id)]));
    return lines.length ? table(["Mount", "Filesystem", "Free", "Backing device"], lines)
      : empty("No storage readings available.");
  }
  function resourceSummary(snapshot) {
    const result = node("span", undefined, "meters");
    const cpu = snapshot?.cpu;
    const memory = snapshot?.memory;
    const gpus = array(snapshot?.gpus);
    const { pools, rows, unmounted } = storageInventory(snapshot);
    const fs = pools.slice().sort((a, b) => a.available_bytes / a.total_bytes - b.available_bytes / b.total_bytes)[0];
    // Bars always fill with what is in use, so a long bar is a busy host on every meter.
    result.append(meterCell("CPU", number(cpu?.utilization_percent) ? `${percent(cpu.utilization_percent)} busy` : "Unknown", cpu ? `${number(cpu.logical_count) ? cpu.logical_count : "Unknown"} logical CPUs` : "No sample",
      number(cpu?.utilization_percent) ? cpu.utilization_percent / 100 : null));
    const memoryKnown = number(memory?.available_bytes) && number(memory?.total_bytes) && memory.total_bytes > 0;
    const memoryUsed = memoryKnown ? 1 - memory.available_bytes / memory.total_bytes : null;
    result.append(meterCell("Memory", number(memory?.available_bytes) ? `${bytes(memory.available_bytes)} free` : "Unknown", `of ${bytes(memory?.total_bytes)} physical`, memoryUsed, 0.9));
    const gpuBusy = gpus.filter((gpu) => number(gpu.busy_percent));
    const gpuDetail = [...new Set(gpus.map((gpu) => gpu.memory_kind === "dedicated" && number(gpu.vram_total_bytes) && number(gpu.vram_used_bytes)
      ? `${bytes(Math.max(0, gpu.vram_total_bytes - gpu.vram_used_bytes))} VRAM free`
      : gpu.memory_kind === "shared" ? "shared memory" : "VRAM unknown"))].join(" / ");
    result.append(meterCell(gpus.length > 1 ? `GPU, ${gpus.length} devices` : "GPU", gpuBusy.length ? `${gpus.map((gpu) => percent(gpu.busy_percent)).join(" / ")} busy` : "Unknown", gpuDetail || "No device telemetry",
      gpuBusy.length ? gpus.map((gpu) => number(gpu.busy_percent) ? gpu.busy_percent / 100 : null) : null));
    const mounts = strings(fs?.mounts);
    // A pool seen through several mounts is named by its most recognisable view, not the first one listed.
    const poolLabel = ["/", "/home", "/var/home"].find((mount) => mounts.includes(mount)) || mounts[0] || fs?.id;
    const diskUsed = fs ? 1 - fs.available_bytes / fs.total_bytes : null;
    const unmeasured = rows.filter((row) => !measuredPool(row)).length;  // Boot partitions are measured, just not pools.
    const extra = [unmeasured && `${unmeasured} unmeasured`, unmounted.length && `${unmounted.length} unmounted ${unmounted.length === 1 ? "disk" : "disks"}`].filter(Boolean).join(", ");
    // One bar per writable pool, tightest first; capacities of distinct pools are never summed into one figure.
    const sorted = pools.slice().sort((a, b) => a.available_bytes / a.total_bytes - b.available_bytes / b.total_bytes);
    result.append(meterCell(pools.length > 1 ? `Storage, ${pools.length} pools` : "Storage", fs ? `${bytes(fs.available_bytes)} free` : "Unknown",
      fs ? `${poolLabel} tightest, ${percent((1 - diskUsed) * 100)} free${extra ? `; ${extra}` : ""}` : extra || "No measured writable pool",
      sorted.length ? sorted.map((pool) => 1 - pool.available_bytes / pool.total_bytes) : null, 0.9));
    ["cpu", "memory", "gpus", "storage"].forEach((scope, index) => result.children[index].append(resourceAge(snapshot, scope)));
    return result;
  }
  function hostVerification(host) {
    return { verified: "Host key verified", unverified: "Host key not verified since the last edit", unpinned: "No host key pinned", "no-collector": "No collector" }[host.verification?.state] || "Verification unknown";
  }
  // What an operator would look for on the host itself: the runtime, and the unit or container name.
  function runtimeLabel(backend, scope) {
    const user = typeof scope === "string" && scope.startsWith("user");
    if (backend === "systemd") return user ? "systemd --user" : scope === "system" ? "systemd (system)" : "systemd";
    if (backend === "podman") return user ? "podman (rootless)" : scope === "system" ? "podman (root)" : "podman";
    return text(backend, "Unknown runtime");
  }
  function workloadRuntime(workload) {
    const bindings = array(workload.bindings);
    const primary = bindings.find((binding) => binding.role === "primary") || bindings[0];
    const nativeName = (binding) => {
      const hit = array(workload.bindings_evidence).find((item) => JSON.stringify(item.binding) === JSON.stringify(binding));
      const resource = hit && fleet.resources.find((item) => item.id === strings(hit.matches)[0]);
      const selector = binding.selector || {};
      const name = text(resource?.name, text(selector.name, text(selector.native_id, "unnamed")));
      return /^[0-9a-f]{64}$/.test(name) ? name.slice(0, 12) : name;
    };
    // A member on another runtime than the primary (a container behind a unit) says so.
    const names = bindings.map((binding) => binding.backend === primary.backend ? nativeName(binding) : `${nativeName(binding)} (${runtimeLabel(binding.backend, binding.scope)})`);
    return { label: runtimeLabel(primary?.backend || workload.backend, primary?.scope), names: names.length ? names : ["no binding"],
      unit: !primary ? "No binding" : bindings.length > 1 ? `${nativeName(primary)} +${bindings.length - 1}` : nativeName(primary) };
  }
  function hostLink(id, owner) {
    if (!fleet.hosts.some((host) => host.id === id)) return node("span", hostName(id));
    const link = node("a", hostName(id), "row-link quiet");
    link.href = "#hosts";
    link.title = "Show this host";
    link.dataset.focusKey = `host-of:${owner}`;
    link.addEventListener("click", (event) => { event.preventDefault(); showHost(id); });
    return link;
  }
  function workloadsLink(host, count) {
    const link = node("a", `${count} ${count === 1 ? "workload" : "workloads"}`, "row-link");
    link.href = "#workloads";
    link.title = "Show the workloads defined on this host";
    link.dataset.focusKey = `workloads-on:${host.id}`;
    link.addEventListener("click", (event) => {
      event.preventDefault();
      selectTab("workloads");
      // Filter on the host ID, the same test the count used, so the list is exactly the counted set.
      workloadHostFilter = host.id;
      ui.definedSearch.value = "";
      byId("defined-state").value = "all";
      renderWorkloads();
      byId("host-filter").scrollIntoView({ block: "center" });
      byId("host-filter").focus({ preventScroll: true });
    });
    return link;
  }
  function paseoSummary(paseo) {
    if (paseo.configured === false) return paseo.daemon ? "Paseo discovered, not enabled" : "No Paseo daemon found";
    if (paseo.agents === null) return "Paseo agents unknown";
    const agents = array(paseo.agents);
    return `${agents.length} Paseo ${agents.length === 1 ? "agent" : "agents"}, ${agents.filter((agent) => agent.status === "running").length} running`;
  }
  function paseoDetail(host) {
    const paseo = host.paseo;
    const daemon = paseo.daemon || {};
    const body = node("div", undefined, "record-body");
    body.append(metadata([
      ["Daemon", `${text(daemon.state, "unknown")}, version ${text(daemon.version)}`],
      ["Listen", text(daemon.listen)], ["Server ID", text(daemon.server_id)],
      ["Started", timestamp(daemon.started_at)],
      ["Providers", array(daemon.providers).map((item) => `${text(item.provider)}: ${item.available ? "available" : "unavailable"}`).join("\n") || "Unknown"],
    ]));
    // The agents themselves are listed once, under Agents.
    if (paseo.daemon) body.append(group("div", "body-actions", agentsLink("Show this host's agents", `agent-host-${host.id}`, "row-link")));
    if (paseo.agents === null) body.append(empty("Agents unknown. No Paseo CLI is configured for this host."));
    if (host.observation?.snapshot) body.prepend(resourceAge(host.observation.snapshot, "paseo"));
    return disclosure(`paseo:${host.id}`, paseoSummary(paseo), body);
  }
  function hostDetail(host) {
    const snapshot = host.observation?.snapshot;
    const attempt = host.observation?.last_attempt;
    const body = node("div", undefined, "record-body");
    body.append(metadata([
      ["Host ID", text(host.id)], ["Platform", text(snapshot?.host?.distribution, text(host.platform))],
      ["Architecture", text(snapshot?.host?.architecture, text(host.architecture))],
      ["Hostname", text(snapshot?.host?.hostname)], ["Collector", text(snapshot?.collector, "Not collected")],
      ["Last checked", timestamp(snapshot?.observed_at)],
      ["CPU sample", number(snapshot?.cpu?.sample_seconds) ? `${snapshot.cpu.sample_seconds.toFixed(2)} s between counters` : "Unavailable"],
      ["Declared capabilities", declaredCapabilities(host).join(", ") || "None declared"],
      ["Control", `Checks: ${host.capabilities?.observe === true ? "available" : "unavailable"}. Shell: ${strings(operationPolicy().shell_hosts).includes(host.id) ? "enabled" : "not configured"}. Workload control: configured workloads only.`],
      ["Host facts read", timestamp(snapshot?.resource_observed_at?.host)],
      ["Access", text(host.access)], ["Catalog provenance", text(host.provenance, "Not supplied")],
      ["Latest attempt", attempt ? `${text(attempt.status)}, ${timestamp(attempt.at)}. ${text(attempt.message)}` : "None recorded"],
    ]));
    body.append(metadata([
      ["Connection verification", hostVerification(host)],
      ["Pinned fingerprints", array(host.pins).map((pin) => pin.fingerprint).join("\n")
        || (host.verification?.state === "unpinned" ? "None; SSH uses address-based known_hosts until a key is pinned" : "Not applicable (no SSH collector)")],
    ]));
    const edit = node("button", "Edit host", "button secondary");
    edit.type = "button";
    edit.dataset.focusKey = `edit-host:${host.id}`;
    edit.addEventListener("click", () => openHostEditor(host.id));
    body.append(group("div", "body-actions", edit));
    if (strings(host.attention).length) body.prepend(node("h4", "Needs attention"), list(strings(host.attention), ""));
    if (host.paseo) body.append(paseoDetail(host));
    const integration = node("div", undefined, "record-body");
    const items = array(host.integration?.items);
    const coverageList = node("ul", undefined, "coverage-list");
    items.forEach((item) => {
      const entry = node("li");
      entry.append(node("strong", text(item.label, item.id)), node("span", text(item.status), item.status === "verified" ? "badge" : "badge caution"),
        node("p", text(item.detail, "No detail supplied.")));
      coverageList.append(entry);
    });
    integration.append(items.length ? coverageList : empty("No integration status supplied. No capability is assumed."));
    body.append(disclosure(`integration:${host.id}`, `Integration status: ${text(host.integration?.summary, "unknown")}`, integration));
    body.append(node("h4", "Development environments"));
    const environments = fleet.environments.filter((item) => item.host_id === host.id);
    environments.forEach((item) => body.append(workloadRecord(item, `environment:${host.id}`)));
    if (!environments.length) body.append(empty("No development environments found. That is not proof there are none."));
    if (!snapshot) {
      body.append(empty("No data cached. Resource values are unknown, not zero."));
      if (host.notes) body.append(node("p", host.notes, "section-note"));
      return body;
    }
    body.append(resourceHeading(snapshot, "CPU", "cpu"));
    body.append(metadata([
      ["CPU model", text(snapshot.cpu?.model)], ["Load average (1 min)", number(snapshot.cpu?.load_1m) ? snapshot.cpu.load_1m : "Unknown"],
    ]));
    body.append(resourceHeading(snapshot, "Memory", "memory"), metadata([
      ["Available / total", `${bytes(snapshot.memory?.available_bytes)} / ${bytes(snapshot.memory?.total_bytes)}`],
      ["Swap free / total", `${bytes(snapshot.memory?.swap_free_bytes)} / ${bytes(snapshot.memory?.swap_total_bytes)}`],
    ]));
    body.append(resourceHeading(snapshot, "GPU devices", "gpus"));
    array(snapshot.gpus).forEach((gpu) => body.append(metadata([
      ["Device", `${text(gpu.name)} (${text(gpu.id)})`], ["Driver", text(gpu.driver)], ["Memory kind", text(gpu.memory_kind)],
      ["Busy", percent(gpu.busy_percent)], ["VRAM used / total", `${bytes(gpu.vram_used_bytes)} / ${bytes(gpu.vram_total_bytes)}`],
    ])));
    if (!array(snapshot.gpus).length) body.append(empty("No GPU telemetry available."));
    body.append(node("p", "Shared GPU memory is not extra physical RAM. Telemetry is not a placement budget.", "section-note"));
    body.append(resourceHeading(snapshot, "Storage", "storage"), storageTable(snapshot));
    body.append(node("p", "Real storage only: block-backed and network filesystems, plus disks with nothing mounted. Mount views of one pool share capacity, so pools are never added together. RAM, image and pseudo filesystems are in the raw data below.", "section-note"));
    body.append(node("h4", "Data sources"));
    const coverage = array(host.coverage);
    const scopes = node("ul", undefined, "coverage-list");
    coverage.forEach((scope) => {
      const item = node("li");
      item.append(node("strong", text(scope.scope)), node("span", text(scope.status), scope.status === "complete" ? "badge" : "badge caution"),
        ageNode(scope.observed_at, scope.freshness, scope.freshness_ttl_seconds), node("p", text(scope.message, "No additional detail")));
      scopes.append(item);
    });
    body.append(coverage.length ? scopes : empty("Coverage not supplied."));
    if (array(snapshot.warnings).length) body.append(node("h4", "Warnings"), list(strings(snapshot.warnings), ""));
    body.append(evidence(`host-evidence:${host.id}`, snapshot));
    return body;
  }
  function hostRow(host) {
    const observation = host.observation || {};
    const snapshot = observation.snapshot;
    const attempt = observation.last_attempt;
    const shell = strings(operationPolicy().shell_hosts).includes(host.id);
    const article = node("article", undefined, `host-row${snapshot ? "" : " is-dark"}`);
    article.dataset.hostRow = host.id;
    // Partial data is routine and already counted beside the last-checked time; only a failed or deferred check changes the lamp.
    const failed = hostErrors.has(host.id) || attempt?.status === "error";
    const aspect = !snapshot ? "dark" : failed ? "fail" : ["busy", "collecting"].includes(attempt?.status) ? "transit" : "run";
    const verification = host.verification?.state;
    const hosted = fleet.workloads.filter((workload) => sourceId(workload) === host.id).length;
    const identity = group("span", "row-identity",
      group("h3", "row-name", lamp(aspect, { run: "Reporting", transit: "Check running or deferred", fail: "Last check failed", dark: "No data" }[aspect]), node("span", hostLabel(host))),
      group("span", "row-sub", node("span", text(host.name, host.id)), hostLabel(host) !== host.id && node("span", text(host.id), "machine"),
        node("span", `${text(host.platform)} ${text(host.architecture)}`),
        hosted > 0 && workloadsLink(host, hosted),
        shell && group("span", "authority is-granted", flag(), "Shell enabled"),
        host.paseo?.daemon && agentsLink(paseoSummary(host.paseo), `agent-host-${host.id}`, "row-link"),
        !snapshot && ["unverified", "unpinned"].includes(verification) && node("span", hostVerification(host))));
    // A connection that changed since it was last proven matters on a host we are reading from.
    if (snapshot && ["unverified", "unpinned"].includes(verification)) identity.append(node("span", hostVerification(host), "row-attention"));
    locksForHost(host).forEach((lock) => {
      const held = lock.state === "held" && !lock.anomaly;
      const link = agentsLink(lock.state === "held" ? `Locked by ${array(lock.holders).map(holderLabel).join(", ") || "an unknown holder"}` : `Lock needs a look: ${text(lock.device)}`,
        `lock-${lock.device}`, held ? "row-link authority is-granted" : "row-link caution");
      if (held) link.prepend(flag());
      identity.append(group("span", "row-sub", link));
    });
    const coverage = array(host.coverage);
    const complete = coverage.filter((scope) => scope.status === "complete").length;
    // Name the data sources that fell short. The server's own notes restate them per source, so those are folded in here.
    const sources = new Set(coverage.map((scope) => scope.scope));
    const notes = [...coverage.filter((scope) => scope.status !== "complete").map((scope) => `${text(scope.scope)} ${text(scope.status)}`),
      ...strings(host.attention).filter((note) => !sources.has(note.split(": ")[0]) && note !== "No fresh host observation")];
    if (cacheReadFailed) notes.push("Showing last-known data");
    if (["error", "busy"].includes(attempt?.status) && !notes.some((note) => /collection/i.test(note))) notes.push(`Last check: ${attempt.status}`);
    if (hostErrors.has(host.id)) notes.unshift(hostErrors.get(host.id));
    // Two notes fit a row; the detail lists them all.
    const attention = snapshot && notes.length ? node("span", `${notes.slice(0, 2).join(". ")}${notes.length > 2 ? `, and ${notes.length - 2} more in the detail` : ""}`, "row-attention") : null;
    const summary = group("span", "host-summary", identity);
    if (snapshot) {
      summary.append(resourceSummary(snapshot), group("span", "row-sample", node("span", "Last checked", "meter-label"),
        ageNode(snapshot.observed_at, observation.freshness, observation.freshness_ttl_seconds, article),
        node("span", coverage.length ? `${complete} of ${coverage.length} data sources OK` : "Data sources unknown", "row-sub"), attention));
    } else {
      summary.append(node("span", hostErrors.get(host.id) || (host.collection_enabled ? canObserve(host) ? "Never checked" : "Checks unavailable" : "No collector configured"), "row-note"));
    }
    const details = disclosure(`host:${host.id}`, summary, hostDetail(host), "row-details");
    const actions = node("div", undefined, "row-actions");
    if (canObserve(host)) {
      const button = node("button", "Check now", "button secondary");
      button.title = "Run this host's collector now";
      button.type = "button";
      button.dataset.observeHost = host.id;
      button.dataset.focusKey = `observe:${host.id}`;
      button.setAttribute("aria-label", `Check ${hostLabel(host)} now`);
      button.addEventListener("click", () => observeHost(host.id));
      updateObserveButton(button, host);
      actions.append(button);
    }
    if (shell) {
      const button = node("button", "Open shell", "button quiet");
      button.type = "button";
      button.dataset.focusKey = `shell:${host.id}`;
      button.setAttribute("aria-label", `Open shell on ${hostLabel(host)}`);
      button.addEventListener("click", () => openShell(host.id));
      actions.append(button);
    }
    article.append(details, actions);
    return article;
  }
  function renderHosts() {
    if (!fleet) return;
    rerender(ui.hosts, () => {
      const query = ui.hostSearch.value.trim().toLocaleLowerCase();
      const hosts = fleet.hosts.filter((host) => matches(host, query)).sort((a, b) =>
        Number(Boolean(b.observation?.snapshot)) - Number(Boolean(a.observation?.snapshot))
        || Number(b.collection_enabled === true) - Number(a.collection_enabled === true));
      const observed = hosts.filter((host) => host.observation?.snapshot);
      const dark = hosts.filter((host) => !host.observation?.snapshot);
      ui.hostCount.textContent = `${observed.length} reporting, ${fleet.hosts.length} in the catalog${hosts.length < fleet.hosts.length ? `, ${hosts.length} shown` : ""}`;
      ui.hosts.replaceChildren(...observed.map(hostRow));
      if (dark.length) ui.hosts.append(group("h3", "group-heading", "No data ", node("span", String(dark.length), "count")), ...dark.map(hostRow));
      if (!hosts.length) ui.hosts.append(empty(query ? "No hosts match. Clear the filter to see all hosts." : "This catalog declares no hosts."));
    });
  }

  // --- Agents and device locks ---
  function agentsLink(label, targetId, className = "") {
    const link = node("a", label, className);
    link.href = "#agents";
    link.dataset.focusKey = `agents:${targetId}:${label}`;
    link.addEventListener("click", (event) => {
      event.preventDefault();
      selectTab("agents");
      const target = byId(targetId);
      if (target) locate(target); else byId("tab-agents").focus();
    });
    return link;
  }
  function holderLabel(holder) {
    return text(holder.paseo_agent_name, `${text(holder.comm, "unknown process")} (pid ${holder.pid ?? "unknown"})`);
  }
  function locksForHost(host) {
    return array(agentsData?.locks).filter((lock) => (lock.state === "held" || lock.anomaly) && strings(lock.host_ids).includes(host.id));
  }
  function devicesHeldBy(agentId) {
    return array(agentsData?.locks).filter((lock) => lock.state === "held"
      && array(lock.holders).some((holder) => holder.paseo_agent_id === agentId)).map((lock) => text(lock.device));
  }
  const LOCK_ANOMALIES = {
    "held-after-release": "Still held after the ledger recorded a release. The holding process owns the kernel lock.",
    "claim-without-holder": "The ledger shows a claim but nothing holds the lock. The process may have exited without recording a release.",
  };
  function lockRow(lock) {
    const holders = array(lock.holders);
    const entries = array(lock.last_entries);
    const latest = entries[entries.length - 1];
    const lease = lock.switchyard_lease;
    const hostNames = strings(lock.host_ids).map((id) => hostName(id)).join(", ") || "No host assigned";
    const state = node("span", undefined, "lock-state");
    if (lock.state === "held") {
      state.append(group("span", "authority is-granted", flag(), `Held by ${holders.map(holderLabel).join(", ") || "an unknown holder"}`));
      const started = holders.map((item) => item.started_at).filter(Boolean)[0];
      if (started) state.append(node("span", `Process started ${ageLabel(ageSeconds(started))}`, "row-sub"));
      if (lease) state.append(node("span", lease.expires_at ? `Lease expires ${clock(lease.expires_at)}` : "Lease ends when its command completes", "row-sub"));
      if (lease?.suspect) state.append(node("span", `Connection lost ${ageLabel(ageSeconds(lease.suspect_since))} (${text(lease.suspect_cause, "unknown cause")}); the remote command may still be running. Held on purpose until released.`, "row-attention"));
    } else if (lock.state === "free") state.append(node("span", lock.blocked ? "Free, but blocked" : "Free", "authority"));
    else state.append(group("span", "cell-state", lamp("dark"), sentence(text(lock.state, "unknown"))));
    if (lock.blocked) state.append(node("span", lock.blocked.error ? `Blocked: ${text(lock.blocked.error)}`
      : `Blocked since a lease was broken ${ageLabel(ageSeconds(lock.blocked.at))} by ${text(lock.blocked.operator, "the operator")} (${text(lock.blocked.reason, "no reason given")}). New leases are refused until: switchyard lease clear ${text(lock.device).toLocaleLowerCase()} --attest-stopped "…"`, "row-attention"));
    const summary = group("span", "lock-summary", node("strong", text(lock.device), "lock-device"), node("span", hostNames, "lock-hosts"), state,
      node("span", latest ? `${{ CLAIM: "Claimed", RELEASE: "Released" }[latest.event] || sentence(text(latest.event).toLocaleLowerCase())} ${ageLabel(ageSeconds(latest.at))} by ${text(latest.owner, "an unnamed owner")}` : "No ledger entries", "lock-ledger"),
      lock.anomaly && node("span", LOCK_ANOMALIES[lock.anomaly] || text(lock.anomaly), "row-attention"));
    const body = node("div", undefined, "record-body");
    body.append(metadata([["Ledger", text(lock.path)],
      ...(lease ? [["Switchyard lease", text(lease.lease_id)], ["Owner", text(lease.owner)], ["Scope", text(lease.scope)],
        ["Expires", lease.expires_at ? timestamp(lease.expires_at) : "When its command completes"],
        ["Holder unit", text(lease.holder_unit, "Foreground command")]] : []),
      ...holders.map((item) => [holderLabel(item), `${text(item.cmdline)}\n${text(item.cwd)}\nStarted ${timestamp(item.started_at)}`])]),
    node("h4", "Recent ledger entries"),
    entries.length ? table(["Event", "When", "Owner", "Scope"], entries.slice().reverse().map((entry) => [text(entry.event), timestamp(entry.at), text(entry.owner), text(entry.scope, "")]))
      : empty("No ledger entries available."));
    const details = disclosure(`lock:${lock.device}`, summary, body, "row-details lock-row");
    details.id = `lock-${lock.device}`;
    return details;
  }
  const AGENT_ASPECTS = { running: "run", idle: "idle", closed: "done", error: "fail", failed: "fail" };
  function agentRow(agent) {
    const devices = devicesHeldBy(agent.id);
    return group("div", "agent-row",
      group("span", "agent-name", lamp(AGENT_ASPECTS[agent.status] || "dark", sentence(text(agent.status, "unknown"))), node("span", text(agent.name, text(agent.short_id, agent.id)))),
      node("span", sentence(text(agent.status, "unknown")), "agent-status"),
      node("span", text(agent.provider), "agent-provider"),
      node("span", text(agent.cwd), "machine agent-cwd"),
      // Paseo reports creation as relative text at collection time when it has no timestamp; show it as reported.
      node("span", number(ageSeconds(agent.created_at)) ? `Created ${ageLabel(ageSeconds(agent.created_at))}` : `Created ${text(agent.created_at, "at an unknown time")}`, "agent-created"),
      devices.length ? group("span", "authority is-granted", flag(), `Holds ${devices.join(", ")}`) : null);
  }
  function agentHost(host) {
    const paseo = host.paseo;
    const daemon = paseo.daemon;
    const agents = paseo.agents === null || paseo.agents === undefined ? null : array(paseo.agents);
    const article = node("article", undefined, "agent-host");
    article.id = `agent-host-${host.host_id}`;
    article.tabIndex = -1;
    const running = agents ? agents.filter((agent) => agent.status === "running").length : 0;
    article.append(group("div", "agent-host-head", node("h4", text(host.hostname, text(host.host_id))),
      node("span", agents ? `${agents.length} ${agents.length === 1 ? "agent" : "agents"}, ${running} running` : "Agents unknown", "count"),
      node("span", host.freshness === "never" ? "Never checked" : `${sentence(text(host.freshness, "unknown"))}, ${ageLabel(ageSeconds(host.observed_at))}`,
        host.freshness === "fresh" ? "agent-freshness" : "agent-freshness caution")));
    const providers = array(daemon.providers);
    const available = providers.filter((item) => item.available).map((item) => text(item.provider));
    const unavailable = providers.filter((item) => !item.available).map((item) => text(item.provider));
    article.append(node("p", `Paseo ${text(daemon.version, "version unknown")}, ${text(daemon.state, "state unknown")}, listening on ${text(daemon.listen, "an unknown address")}.`
      + `${available.length ? ` Providers available: ${available.join(", ")}.` : ""}${unavailable.length ? ` Unavailable: ${unavailable.join(", ")}.` : ""}`, "section-note"));
    if (paseo.configured === false) {
      const enable = node("button", "Enable Paseo", "button secondary");
      enable.type = "button";
      enable.dataset.focusKey = `enable-paseo:${host.host_id}`;
      enable.addEventListener("click", () => openPaseoEditor(host.host_id));
      article.append(node("p", "A Paseo daemon was found here, but reading it is not enabled, so its agents are not listed.", "section-note"), group("div", "body-actions", enable));
    }
    if (!agents) article.append(empty("Agents unknown. No Paseo CLI is configured for this host, or its metadata was unavailable."));
    else if (!agents.length) article.append(empty("No agents reported. Archived agents are not listed."));
    else {
      // Working agents are the ones that can hold a device; the rest wait behind one line.
      const working = agents.filter((agent) => !["idle", "closed"].includes(agent.status));
      const resting = agents.filter((agent) => ["idle", "closed"].includes(agent.status));
      if (working.length) article.append(group("div", "agent-list", ...working.map(agentRow)));
      if (resting.length) {
        const idle = resting.filter((agent) => agent.status === "idle").length;
        const label = [idle && `${idle} idle`, resting.length - idle && `${resting.length - idle} closed`].filter(Boolean).join(", ");
        article.append(disclosure(`agents-resting:${host.host_id}`, working.length ? label : `No agent is running. ${label}`, group("div", "agent-list", ...resting.map(agentRow))));
      }
    }
    return article;
  }
  function renderAgents() {
    if (!agentsData) return;
    const hosts = array(agentsData.hosts);
    const withDaemon = hosts.filter((host) => host.paseo?.daemon);
    const everyAgent = withDaemon.flatMap((host) => array(host.paseo.agents));
    byId("agents-count").textContent = withDaemon.length
      ? `${everyAgent.length} ${everyAgent.length === 1 ? "agent" : "agents"} on ${withDaemon.length} ${withDaemon.length === 1 ? "host" : "hosts"}, ${everyAgent.filter((agent) => agent.status === "running").length} running` : "";
    rerender(byId("agents-list"), () => {
      const rows = withDaemon.map(agentHost);
      const missing = hosts.filter((host) => !host.paseo?.daemon).map((host) => text(host.hostname, text(host.host_id)));
      if (missing.length) rows.push(node("p", `No Paseo daemon found on ${missing.join(", ")}.`, "section-note agents-not-found"));
      byId("agents-list").replaceChildren(...(rows.length ? rows : [empty("No hosts in the cache yet. Check a host to look for Paseo.")]));
    });
    rerender(byId("device-locks"), () => {
      const locks = array(agentsData.locks).slice().sort((a, b) => text(a.device).localeCompare(text(b.device)));
      const notable = locks.filter((lock) => lock.state !== "free" || lock.anomaly || lock.blocked);
      const free = locks.filter((lock) => !notable.includes(lock));
      const held = locks.filter((lock) => lock.state === "held").length;
      const unknown = notable.filter((lock) => lock.state !== "held").length;
      byId("locks-count").textContent = locks.length ? [`${held} held`, unknown && `${unknown} unknown or flagged`, `${free.length} free`].filter(Boolean).join(", ") : "";
      const rows = notable.sort((a, b) => Number(b.state === "held") - Number(a.state === "held")).map(lockRow);
      if (free.length) rows.push(disclosure("locks-free", `${free.length} free: ${free.map((lock) => text(lock.device)).join(", ")}`, group("div", "lock-free-list", ...free.map(lockRow)), "record lock-free"));
      byId("device-locks").previousElementSibling.hidden = !notable.length;
      byId("device-locks").replaceChildren(...(rows.length ? rows : [empty("No device ledgers found.")]));
    });
  }
  async function loadAgents() {
    if (agentsLoading || pageClosed) return;
    agentsLoading = true;
    byId("refresh-agents").disabled = true;
    error(byId("agents-error"), "");
    try {
      const data = await api("/api/agents");
      if (!Array.isArray(data.hosts) || !Array.isArray(data.locks)) throw new Error("Agents response did not match the cached metadata contract.");
      // This runs on every cached update; rebuild the lists only when something actually changed.
      const signature = JSON.stringify(data);
      if (signature !== agentsSignature) {
        agentsSignature = signature;
        agentsData = data;
        renderAgents();
        renderHosts();
      }
      byId("agents-status").textContent = `Read ${clock(Date.now())}.`;
    } catch (cause) {
      error(byId("agents-error"), cause.message);
      byId("agents-status").textContent = agentsData ? "Reload failed. Showing the last agents and lock state received." : "Agents and locks unavailable. Reload to try again.";
    } finally { agentsLoading = false; byId("refresh-agents").disabled = false; }
  }
  function paseoEditorControls() {
    const stale = paseoReviewed && fleet?.registry_revision && paseoReviewed.fleetRevision !== fleet.registry_revision
      && paseoReviewed.revision !== fleet.registry_revision;
    paseoEditor.save.disabled = paseoPending || !paseoReviewed || Boolean(stale);
    byId("review-paseo").disabled = paseoPending || !paseoDraft;
    byId("close-paseo-editor").disabled = paseoPending;
    [paseoEditor.listen, paseoEditor.cli].forEach((field) => { field.disabled = paseoPending || !paseoDraft; });
    if (stale) paseoEditor.status.textContent = "The host registry changed. Your draft is kept. Review current configuration again before saving.";
  }
  function fillPaseoCandidates(candidates, selected) {
    paseoEditor.cli.replaceChildren(new Option("HTTP-only (agents unknown)", ""),
      ...candidates.map((candidate) => new Option(candidate, candidate)));
    if (selected && !candidates.includes(selected)) paseoEditor.cli.append(new Option(`${selected} (no longer detected)`, selected));
    paseoEditor.cli.value = selected;
  }
  async function openPaseoEditor(hostId) {
    if (paseoPending) return;
    selectTab("agents");
    paseoEditor.panel.hidden = false;
    if (paseoDraft) {
      paseoEditor.status.textContent = "Your existing draft is kept. Finish it or close the editor before enabling another host.";
      paseoEditor.panel.scrollIntoView({ block: "nearest" });
      return;
    }
    paseoPending = true;
    paseoEditorControls();
    error(paseoEditor.error, "");
    try {
      const registry = await api("/api/hosts");
      const host = array(registry.hosts).find((item) => item.id === hostId);
      const observed = array(agentsData?.hosts).find((item) => item.host_id === hostId);
      if (!host || !observed?.paseo?.daemon) throw new Error("That discovered Paseo host is no longer available. Refresh agents.");
      paseoDraft = { hostId };
      paseoReviewed = null;
      paseoEditor.listen.value = host.collector?.paseo?.listen || "127.0.0.1:6767";
      const candidates = strings(observed.paseo.cli_candidates);
      fillPaseoCandidates(candidates, candidates[0] || "");
      byId("paseo-editor-title").textContent = `Enable Paseo on ${hostName(host.id)}`;
      paseoEditor.review.replaceChildren();
      paseoEditor.status.textContent = "Choose a detected CLI or HTTP-only, then review the current saved configuration.";
    } catch (cause) { error(paseoEditor.error, cause.message); }
    finally {
      paseoPending = false;
      paseoEditorControls();
      paseoEditor.panel.scrollIntoView({ block: "nearest" });
      if (paseoDraft) paseoEditor.listen.focus({ preventScroll: true });
    }
  }
  async function reviewPaseo(event) {
    event.preventDefault();
    if (!paseoDraft || paseoPending) return;
    paseoPending = true;
    paseoReviewed = null;
    paseoEditorControls();
    error(paseoEditor.error, "");
    try {
      const [registry, observed] = await Promise.all([api("/api/hosts"), api("/api/agents")]);
      const current = array(registry.hosts).find((host) => host.id === paseoDraft.hostId);
      if (!current?.collector) throw new Error("That host no longer has a collector. Your draft is kept.");
      const candidates = strings(array(observed.hosts).find((host) => host.host_id === paseoDraft.hostId)?.paseo?.cli_candidates);
      const selected = paseoEditor.cli.value;
      fillPaseoCandidates(candidates, selected);
      if (selected && !candidates.includes(selected)) throw new Error("The selected CLI is no longer detected. Your draft is kept; choose a current one or HTTP-only.");
      const payload = { host_id: paseoDraft.hostId, enabled: true, listen: paseoEditor.listen.value.trim(),
        cli: paseoEditor.cli.value || null, expected_revision: registry.revision };
      paseoReviewed = { payload, revision: registry.revision, fleetRevision: fleet?.registry_revision };
      paseoEditor.review.replaceChildren(evidence("paseo-current", current.collector.paseo || null, "Current saved Paseo configuration"),
        evidence("paseo-changes", payload, "Exact configuration to save"));
      paseoEditor.status.textContent = "Review the current configuration and exact change. Enable saves only at this registry revision; no host is contacted.";
    } catch (cause) { error(paseoEditor.error, cause.message); paseoEditor.status.textContent = "Review failed. Your draft is kept."; }
    finally { paseoPending = false; paseoEditorControls(); }
  }
  async function savePaseo() {
    if (paseoEditor.save.disabled || !paseoReviewed) return;
    paseoPending = true;
    paseoEditorControls();
    error(paseoEditor.error, "");
    try {
      await api("/api/hosts/paseo", paseoReviewed.payload);
      paseoDraft = null;
      paseoReviewed = null;
      paseoEditor.review.replaceChildren();
      paseoEditor.status.textContent = "Paseo enabled. No host was contacted. The next full inventory check will read agent metadata.";
      await loadFleet();
    } catch (cause) {
      paseoReviewed = null;
      error(paseoEditor.error, cause.message);
      paseoEditor.status.textContent = "Save not confirmed. Your draft is kept. Review current configuration again; nothing is overwritten or retried.";
    } finally { paseoPending = false; paseoEditorControls(); }
  }
  function openShell(hostId) {
    selectTab("hosts");
    op.shellPanel.open = true;
    op.shellHost.value = hostId;
    operationControls();
    op.shellPanel.scrollIntoView({ block: "start" });
    op.script.focus({ preventScroll: true });
  }

  // --- Workloads and discovery ---
  // The private Commons capability URL is browser-local, never part of fleet metadata or an API request.
  const COMMONS_SESSION_KEY = "switchyard.commons-dashboard";
  // Commons integrations use workload roles, never a private host or resident allowlist.
  const COMMONS_WORKLOAD = /^(?:commons(?:-station)?|resident-[A-Za-z0-9_.-]+)$/;
  const commonsHandoff = {
    panel: byId("commons-handoff"), form: byId("commons-handoff-form"), input: byId("commons-handoff-url"),
    status: byId("commons-handoff-status"), error: byId("commons-handoff-error"), returnKey: null,
  };
  function commonsDashboardUrl(value) {
    if (typeof value !== "string" || value.length > 8192 || !/^https?:\/\//i.test(value.trim())) return null;
    try {
      const url = new URL(value.trim());
      if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password || url.search) return null;
      url.hash = "";
      return url.href;
    } catch { return null; }
  }
  function savedCommonsDashboard() {
    try { return commonsDashboardUrl(window.sessionStorage.getItem(COMMONS_SESSION_KEY)); }
    catch { return null; }
  }
  function canUseCommonsHandoff() {
    return Boolean(fleet) && fleet.read_only_view !== true && !signedOut && !auth?.login_required
      && ["operator", "local"].includes(auth?.kind);
  }
  function closeCommonsHandoff() {
    commonsHandoff.panel.hidden = true;
    commonsHandoff.input.value = "";
    Array.from(ui.workloads.querySelectorAll("[data-focus-key]"))
      .find((item) => item.dataset.focusKey === commonsHandoff.returnKey)?.focus({ preventScroll: true });
  }
  function openCommonsHandoff(id) {
    if (!canUseCommonsHandoff()) return;
    commonsHandoff.returnKey = `commons-settings:${id}`;
    commonsHandoff.input.value = "";
    commonsHandoff.status.textContent = savedCommonsDashboard() ? "A private link is saved for this tab. Paste a new URL to replace it, or forget it below." : "No private link is saved for this tab.";
    error(commonsHandoff.error, "");
    commonsHandoff.panel.hidden = false;
    commonsHandoff.panel.scrollIntoView({ block: "nearest" });
    commonsHandoff.input.focus({ preventScroll: true });
  }
  function commonsHandoffActions(id) {
    if (!COMMONS_WORKLOAD.test(id) || !canUseCommonsHandoff()) return null;
    const base = savedCommonsDashboard();
    const slug = id.startsWith("resident-") && !id.startsWith("resident-caretaker-") ? id.slice(9) : "";
    const resident = slug ? slug.charAt(0).toUpperCase() + slug.slice(1) : "";
    const label = `${resident || "Residents"} · Commons controls`;
    const controls = group("span", "row-sub row-links control-only");
    if (base) {
      const link = node("a", label, "row-link");
      link.href = base + "#residents" + (resident ? `?resident=${encodeURIComponent(resident)}` : "");
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.referrerPolicy = "no-referrer";
      link.dataset.focusKey = `commons-controls:${id}`;
      controls.append(link);
    }
    const settings = node("button", base ? "Link settings" : `Set up ${label}`, "row-link commons-link-settings");
    settings.type = "button";
    settings.dataset.focusKey = `commons-settings:${id}`;
    settings.addEventListener("click", () => openCommonsHandoff(id));
    controls.append(settings);
    return controls;
  }
  commonsHandoff.form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!canUseCommonsHandoff()) return;
    const url = commonsDashboardUrl(commonsHandoff.input.value);
    commonsHandoff.input.value = "";
    if (!url) {
      error(commonsHandoff.error, "Use an absolute HTTP or HTTPS dashboard URL without a username, password or query string.");
      return;
    }
    try { window.sessionStorage.setItem(COMMONS_SESSION_KEY, url); }
    catch {
      error(commonsHandoff.error, "This browser could not save session storage. No link was saved.");
      return;
    }
    error(commonsHandoff.error, "");
    commonsHandoff.status.textContent = "Private link saved for this tab only. Open a row's Commons controls to continue there; nothing was started or stopped.";
    renderWorkloads();
  });
  byId("forget-commons-handoff").addEventListener("click", () => {
    if (!canUseCommonsHandoff()) return;
    commonsHandoff.input.value = "";
    try { window.sessionStorage.removeItem(COMMONS_SESSION_KEY); }
    catch {
      error(commonsHandoff.error, "This browser could not clear session storage. Close this tab to discard its session.");
      return;
    }
    error(commonsHandoff.error, "");
    commonsHandoff.status.textContent = "Private link forgotten for this tab.";
    renderWorkloads();
  });
  byId("close-commons-handoff").addEventListener("click", closeCommonsHandoff);

  function containerOrigin(container) {
    // Labels written at creation are provenance claims, not proof the manifest or unit still exists.
    const parts = [];
    if (container.project) parts.push(`Compose project ${container.project}${container.service ? `, service ${container.service}` : ""}`);
    if (container.systemd_unit) parts.push(`systemd unit label ${container.systemd_unit}`);
    return parts.join("; ") || "No Compose or Quadlet labels; created directly or by an unlabelled tool";
  }
  function workloadRecord(workload, context = "discovery", role = "") {
    const body = node("div", undefined, "record-body");
    const container = workload.extensions?.["container.v1"];
    body.append(metadata([
      ["ID", text(workload.id)], ["Host", hostName(sourceId(workload))], ["Runtime", runtimeLabel(workload.backend, workload.scope)],
      ["Scope", text(workload.scope)], ["Native ID", text(workload.native_id)], ["Kind", text(workload.kind)],
      ...(container && container.image_reference ? [
        ["Image", `${text(container.image_reference)} (${text(container.image_id).replace(/^sha256:/, "").slice(0, 12)})`],
        ["Origin", containerOrigin(container)],
        ...(container.compose_directory ? [["Compose directory", text(container.compose_directory)]] : []),
        ...(array(container.compose_files).length ? [["Compose files", strings(container.compose_files)
          .map((file) => file.startsWith("/") || !container.compose_directory ? file : `${container.compose_directory}/${file}`).join("\n")]] : []),
      ] : []),
      ["Health", text(workload.health, "unknown")],
      ["Control", "None: discovered, read-only"], ["Last checked", timestamp(workload.observed_at)],
    ]), evidence(`${context}:resource-evidence:${workload.id}`, workload.extensions || {}));
    if (["service", "scheduled-job"].includes(workload.kind) && !fleet.environments.some((item) => item.id === workload.id)) {
      const promote = node("button", "Define workload", "button secondary");
      promote.type = "button";
      promote.addEventListener("click", () => openDefinition(workload));
      body.append(group("div", "body-actions", promote), node("p", "Defining a workload records a name and which units or containers belong to it. It does not grant restart or deployment permission.", "field-note"));
    }
    const summary = group("span", "record-summary");
    summary.append(lifecycleLamp(workload.lifecycle), node("span", text(workload.name, workload.native_id), "record-name"),
      role && node("span", role, "badge"),
      node("span", sentence(text(workload.lifecycle, "unknown")), workload.lifecycle === "failed" ? "record-state danger" : "record-state"));
    if (container?.image_reference) summary.append(node("span", container.project ? `${container.image_reference}, project ${container.project}` : container.image_reference, "record-origin"));
    if (text(workload.health, "unknown") !== "unknown") summary.append(node("span", `health ${workload.health}`, "badge"));
    summary.append(ageNode(workload.observed_at, workload.freshness, workload.freshness_ttl_seconds, summary));
    return disclosure(`${context}:resource:${workload.id}`, summary, body);
  }
  function definitionRecord(workload) {
    const managed = managedWorkload(workload.id);
    const article = node("article", undefined, "roster-row");
    article.dataset.workloadRow = workload.id;
    if (operationsOpen && managed && op.workload.value === workload.id) article.classList.add("is-selected");
    const placement = workload.managed_placement;
    const placementState = placement ? text(placement.lifecycle, "unknown") : null;
    const uncertain = placement && (placement.uncertain || ["unknown", "needs-inspection"].includes(placementState));
    const runtime = workloadRuntime(workload);
    // How Switchyard relates to it, from the workload store: observed (watched only), registered (described by its
    // owner) or deployed (created by Switchyard).
    const relation = text(workload.management, "observed");
    const registered = relation === "registered";
    const partOf = workload.part_of;
    const partOfApp = partOf && fleet.workloads.find((item) => item.id === partOf.application_id);
    const identity = group("span", "row-identity",
      group("h3", "row-name", lifecycleLamp(workload.lifecycle), node("span", text(workload.name, workload.id))),
      group("span", "row-sub row-purpose", text(workload.purpose, "No purpose supplied.")),
      partOf && node("span", `Part of ${text(partOfApp?.name, partOf.application_id)} (component ${text(partOf.component)})`, "row-sub"),
      workloadLanLinks(workload.id),
      commonsHandoffActions(workload.id),
      uncertain && node("span", "Where this runs is unverified. Inspect it before acting.", "row-attention"));
    const stateText = registered && workload.lifecycle_summary ? workload.lifecycle_summary : sentence(text(workload.lifecycle, "unknown"));
    const summary = group("span", "roster-summary", identity,
      group("span", "roster-host", hostLink(sourceId(workload), workload.id)),
      group("span", "roster-runtime", node("span", runtime.label), node("span", runtime.unit, "machine row-sub")),
      node("span", stateText, workload.lifecycle === "failed" ? "roster-state danger" : "roster-state"),
      ageNode(workload.observed_at, workload.freshness, workload.freshness_ttl_seconds, article),
      managed ? group("span", "authority is-granted", flag(), "Managed")
        : relation === "deployed" ? group("span", "authority is-granted", flag(), "Deployed")
          : registered ? node("span", "Registered", "authority") : node("span", "Observed", "authority"));
    summary.lastElementChild.title = managed ? "Control actions are configured for this workload. Each one needs your approval."
      : relation === "deployed" ? "Deployed by Switchyard. No workload control actions are currently authorized."
        : registered ? "Registered by its owner. Switchyard shows it and may hold start tokens; it has no lifecycle control."
          : "Observed only. No control actions are configured for this workload.";
    const body = node("div", undefined, "record-body");
    const deployment = workload.deployment;
    if (deployment) {
      // Deployed by Switchyard: identity and intent come from the deploy journal, running state from the host's monitoring.
      const verified = deployment.last_verified;
      const drift = verified ? strings(verified.drift) : [];
      const count = (value) => (number(value) ? String(value) : "unknown");
      const devices = Array.isArray(deployment.devices) ? deployment.devices : [];
      const exclusive = Array.isArray(deployment.exclusive) ? deployment.exclusive : [];
      body.append(node("p", `Deployed by Switchyard from template ${text(deployment.template_ref?.id)} (revision ${count(deployment.template_ref?.revision)}). `
        + "This row comes from the deploy journal; its running state comes from monitoring the host.",
        deployment.uncertain || drift.length ? "section-note caution" : "section-note"),
      metadata([
        ["Journal state", `${sentence(text(deployment.state, "unknown"))}${deployment.uncertain ? ", outcome of the last operation unknown: inspect before acting" : ""}`],
        ["Listens on", strings(deployment.claims).join("\n") || "No published ports"],
        ["Generation", count(deployment.generation)],
        ["Start token", sentence(text(deployment.token, "unknown"))],
        ["Service unit", text(deployment.service)],
        ...(devices.length ? [["Host devices", devices.map((device) => `${text(device.host)} → ${text(device.container)} (${text(device.access)}`
          + `${number(device.major) ? `, ${device.major}:${device.minor}` : ""})`).join("\n")]] : []),
        ...exclusive.map((resource) => ["Exclusive resource", `${text(resource.resource)}: ${resource.holding ? "held by this instance" : "not held by this instance"}`
          + ((Array.isArray(resource.contenders) && resource.contenders.length)
            ? "\nAlso declared by: " + resource.contenders.map((other) => `${text(other.instance_id)} (${text(other.state)}${other.holding ? ", holding" : ""})`).join(", ")
            : "\nNo other instance on this host declares it")]),
        ...(deployment.image_pull ? [["Image pull", `${sentence(text(deployment.image_pull.state, "unknown"))}, ${text(deployment.image_pull.reference)}`]] : []),
        ["Last verified against the host", verified
          ? `${timestamp(verified.verified_at)}: ${verified.consistent ? "consistent" : `drift (${drift.join(", ") || "host not observed"})`}`
          : "Never. Run: switchyard deploy verify " + text(deployment.instance_id, workload.id)],
        ["Deployment maintenance", `switchyard deploy refresh-plan | fence | undeploy-plan ${text(deployment.instance_id, workload.id)}`],
      ]));
    }
    if (placement) {
      const verification = placement.uncertain ? "unverified, inspection required" : `last verified ${timestamp(placement.verified_at)}`;
      body.append(node("p", `Managed placement: ${hostName(placement.host_id)}, ${placementState}, ${verification}. This comes from operation results, separately from the collectors.`,
        uncertain ? "section-note caution" : "section-note"),
      disclosure(`placement:${workload.id}`, "Managed placement and recovery data (JSON)",
        node("pre", JSON.stringify(placement, null, 2), "evidence")));
    }
    if (registered) {
      // Registered by its owner: components and placements come from the owner's bundle in the workload store,
      // each component's state from monitoring its host.
      const registration = workload.registration || {};
      body.append(node("p", `Registered by ${text(registration.submitted_by, "its owner")} (registration revision ${number(registration.revision) ? String(registration.revision) : "unknown"}). `
        + "Switchyard shows it and may hold its start tokens; it has no lifecycle, deploy or migration authority over it.", "section-note"));
      const components = array(workload.registered_components);
      body.append(components.length ? table(["Component", "Host", "Native", "State", "Last checked", "Also listed as", "Start token"],
        components.map((item) => [
          group("span", "", lifecycleLamp(item.lifecycle), node("span", text(item.component))),
          hostName(item.host_id),
          [text(item.native?.unit, ""), ...strings(item.native?.related_units)].filter(Boolean).join(", ") || text(item.native?.kind),
          sentence(text(item.lifecycle, "unknown")),
          ageNode(item.observed_at, item.freshness, item.freshness_ttl_seconds),
          strings(item.linked_workloads).join(", ") || "None",
          array(item.tokens).map((token) => `${text(token.state)} (generation ${String(token.generation)})`).join(", ") || "None issued",
        ]), "Components of this application") : empty("This registration places no components."));
      strings(registration.warnings).forEach((warning) => body.append(node("p", warning, "section-note caution")));
    }
    body.append(metadata([
      ["Purpose", text(workload.purpose, "No purpose supplied.")],
      ["Runtime", `${runtime.label}: ${runtime.names.join(", ")}`],
      ["State source", text(workload.state_evidence?.kind, "Collector or catalog; see raw data")],
      [registered ? "Application ID" : "Definition ID", workload.id], ["Kind", text(workload.kind)],
      ...(registered ? [["Application health", text(workload.health, "unknown")]] : [
        ["Application health", text(workload.health, "unknown")], ["Health check (description only)", text(workload.health_check, "Not defined")],
        ["Dependencies", strings(workload.dependencies).join(", ") || "None declared"],
        ["Data locations", strings(workload.data_locations).join("\n") || "None declared"]]),
      ["Requirements", strings(workload.requirements).join(", ") || "None declared"],
      ...(relation === "observed" ? [["Migration recipe", workload.recipe ? "Supplied" : "Not supplied; migration is blocked"]] : []),
    ]));
    if (workload.lifecycle_inspection) {
      body.append(evidence(`lifecycle:${workload.id}`, workload.lifecycle_inspection, "Lifecycle inspection and preconditions"));
    }
    // One row per unit or container, marked primary or supporting. How each was matched is in the raw definition below.
    body.append(node("h4", "Units and containers"));
    array(workload.bindings_evidence).forEach((item) => {
      const binding = item.binding || {};
      const found = strings(item.matches).map((id) => fleet.resources.find((resource) => resource.id === id)).filter(Boolean);
      found.forEach((resource) => body.append(workloadRecord(resource, `definition:${workload.id}`,
        item.component ? `${item.component}: ${text(binding.role, "")}` : text(binding.role, ""))));
      if (!found.length) body.append(node("p", `${item.component ? `${item.component}: ` : ""}${sentence(text(binding.role, "member"))} not found on ${item.host_id ? hostName(item.host_id) : "the host"}: ${runtimeLabel(binding.backend, binding.scope)}, selector ${JSON.stringify(binding.selector || {})} (${text(item.status, "status unknown")}).`, "section-note caution"));
    });
    if (!array(workload.bindings_evidence).length) body.append(empty("This definition names no units or containers."));
    body.append(node("p", "A member selected by name matches whatever currently has that name, not one fixed container. The workload's state is its primary member's state, which says nothing about application health.", "field-note"),
      evidence(`bindings:${workload.id}`, workload.bindings, "Definition bindings (JSON)"));
    if (workload.notes) body.append(node("p", workload.notes, "section-note"));
    if (relation === "observed") {
      const edit = node("button", "Edit definition", "button secondary");
      edit.type = "button";
      edit.dataset.focusKey = `edit:${workload.id}`;
      edit.addEventListener("click", () => openDefinition(null, workload.id));
      body.append(group("div", "body-actions", edit));
    }
    article.append(disclosure(`definition:${workload.id}`, summary, body, "row-details"));
    const actions = node("div", undefined, "row-actions");
    if (managed) {
      const button = node("button", "Manage", "button secondary");
      button.type = "button";
      button.dataset.focusKey = `manage:${workload.id}`;
      button.setAttribute("aria-label", `Manage ${text(workload.name, workload.id)}`);
      button.addEventListener("click", () => openOperation(workload.id));
      actions.append(button);
    }
    article.append(actions);
    return article;
  }
  function renderWorkloads() {
    if (!fleet) return;
    rerender(ui.workloads, () => {
      const query = ui.definedSearch.value.trim().toLocaleLowerCase();
      const mode = byId("defined-state").value;
      const wanted = { active: ["running", "idle", "starting", "stopping"], stopped: ["stopped", "completed"] }[mode];
      const needsAttention = (item) => !["running", "idle", "stopped", "completed"].includes(item.lifecycle)
        || freshness(item.observed_at, item.freshness, item.freshness_ttl_seconds) !== "fresh"
        || Boolean(item.managed_placement && (item.managed_placement.uncertain || ["unknown", "needs-inspection"].includes(item.managed_placement.lifecycle)));
      const workloads = fleet.workloads.filter((item) => !workloadHostFilter || sourceId(item) === workloadHostFilter)
        .filter((item) => matches(item, query) || matches(hostName(sourceId(item)), query))
        .filter((item) => mode === "all" || (wanted ? wanted.includes(item.lifecycle) : needsAttention(item)));
      const chip = byId("host-filter");
      chip.hidden = !workloadHostFilter;
      chip.replaceChildren(...(workloadHostFilter ? [node("span", `Host: ${hostName(workloadHostFilter)}`), node("span", "×", "filter-chip-clear")] : []));
      chip.setAttribute("aria-label", workloadHostFilter ? `Showing only workloads on ${hostName(workloadHostFilter)}. Remove this filter.` : "");
      const tally = ["running", "idle", "starting", "stopping", "stopped", "completed", "failed", "unknown"]
        .map((state) => [state, fleet.workloads.filter((item) => text(item.lifecycle, "unknown") === state).length])
        .filter(([, count]) => count).map(([state, count]) => `${count} ${state}`).join(", ");
      ui.workloadCount.textContent = `${workloads.length === fleet.workloads.length ? "" : `${workloads.length} shown of `}${fleet.workloads.length} workloads${tally ? `: ${tally}` : ""}`;
      ui.workloads.classList.toggle("has-actions", array(operationPolicy().workloads).length > 0);
      ui.workloads.previousElementSibling.classList.toggle("has-actions", array(operationPolicy().workloads).length > 0);
      ui.workloads.previousElementSibling.hidden = !workloads.length;
      ui.workloads.replaceChildren(...workloads.map(definitionRecord));
      if (!workloads.length) ui.workloads.append(empty(!fleet.workloads.length ? "No workloads are defined yet. Open Discovered on hosts below, pick a service and choose Define workload."
        : mode === "attention" && !query ? "Nothing needs attention: every workload has a known state and fresh data."
          : "No defined workloads match. Clear the filter or choose All states."));
    });
  }
  function renderMonitoring() {
    const monitor = fleet.monitoring;
    const state = text(monitor.state, "unavailable");
    byId("monitor-summary").textContent = `Automatic monitoring: ${state}`;
    byId("monitor-chip-text").textContent = `Monitoring ${state}`;
    byId("monitor-lamp").className = `lamp lamp-${state === "running" ? "run" : state === "disabled" ? "dark" : "transit"}`;
    byId("monitor-status").textContent = `${text(monitor.message, "No monitor status supplied.")} Last heartbeat ${timestamp(monitor.heartbeat_at)}. Opening this page never starts monitoring.`;
    const hosts = array(monitor.hosts);
    byId("monitor-hosts").replaceChildren(hosts.length ? table(["Host", "CPU and memory", "Storage", "Full inventory", "Next due", "Last result", "Last run took"], hosts.map((host) => [
      hostName(host.host_id), `every ${host.fast_seconds} s`, `every ${host.storage_seconds} s`, `every ${host.inventory_seconds} s`,
      timestamp(host.next_due_at), text(host.last_status, "Not sampled"),
      number(host.last_duration_seconds) ? `${host.last_duration_seconds.toFixed(2)} s` : "Unknown",
    ])) : empty("No hosts are opted in to automatic monitoring."));
  }
  function fillFilters() {
    const records = [...fleet.resources, ...fleet.artifacts, ...fleet.groups];
    [[ui.backend, "backend", "All runtimes"], [ui.scope, "scope", "All scopes"]].forEach(([select, key, label]) => {
      const selected = select.value;
      const values = [...new Set(records.map((item) => item[key]).filter((value) => typeof value === "string" && value))].sort();
      if (selected && selected !== "all" && !values.includes(selected)) values.push(selected);
      const all = node("option", label);
      all.value = "all";
      select.replaceChildren(all);
      values.forEach((value) => {
        const option = node("option", value);
        option.value = value;
        select.append(option);
      });
      select.value = selected || "all";
    });
  }
  function scopeMatches(record) {
    return (ui.backend.value === "all" || record.backend === ui.backend.value)
      && (ui.scope.value === "all" || record.scope === ui.scope.value);
  }
  function inventoryMatches(record, query) {
    return scopeMatches(record) && matches(record, query)
      && (ui.freshness.value === "all" || freshness(record.observed_at, record.freshness, record.freshness_ttl_seconds) === ui.freshness.value);
  }
  function groupHeading(title, backend, scope, count) {
    return group("h3", "group-title", node("span", title), node("span", `${text(backend)} / ${text(scope)}`, "group-scope"), node("span", String(count), "count"));
  }
  function nativeGroups(records, renderRecord, container, prefix = "") {
    const groups = new Map();
    records.forEach((record) => {
      const key = JSON.stringify([record.host_id, record.backend, record.scope]);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(record);
    });
    groups.forEach((items) => {
      const section = node("section", undefined, "workload-group");
      section.append(groupHeading(`${prefix}${hostName(items[0].host_id)}`, items[0].backend, items[0].scope, items.length));
      items.forEach((record) => section.append(renderRecord(record)));
      container.append(section);
    });
  }
  function renderDiscovery() {
    if (!fleet) return;
    rerender(ui.discovery, () => {
      const query = ui.workloadSearch.value.trim().toLocaleLowerCase();
      const applicationMode = ui.grouping.value === "application";
      const matchingGroups = applicationMode ? fleet.groups.filter((item) => scopeMatches(item) && matches(item, query)) : [];
      const groupMemberIds = new Set(matchingGroups.flatMap((item) => strings(item.member_ids)));
      const environments = new Set(fleet.environments.map((item) => item.id));
      const workloads = fleet.resources.filter((workload) => workload.kind !== "environment" && !environments.has(workload.id)).filter((workload) => {
        const lifecycle = ui.lifecycle.value;
        return inventoryMatches(workload, groupMemberIds.has(workload.id) ? "" : query)
          && (lifecycle === "all" || (lifecycle === "active" ? ["running", "idle", "starting", "stopping"].includes(workload.lifecycle) : workload.lifecycle === lifecycle));
      });
      ui.discoveryCount.textContent = `${workloads.length} units and containers`;
      ui.discovery.replaceChildren();
      const groupedIds = new Set();
      if (applicationMode) {
        fleet.groups.filter(scopeMatches).forEach((item) => {
          const ids = new Set(strings(item.member_ids));
          const items = workloads.filter((workload) => ids.has(workload.id));
          const missing = strings(item.missing_native_ids);
          if (!items.length && (!missing.length || !matches(item, query))) return;
          const section = node("section", undefined, "workload-group");
          section.append(groupHeading(text(item.name, item.id), item.backend, item.scope, items.length),
            node("p", `On ${hostName(item.host_id)}. ${items.length} of ${ids.size} members match the filters${missing.length ? `, ${missing.length} not found` : ""}. A grouping found by discovery grants no control.`, "section-note"));
          const body = node("div", undefined, "record-body");
          body.append(metadata([["Source", text(item.provenance)], ["Control", "None: discovered, not managed"]]));
          body.append(node("p", "A group comes from a catalog declaration or a compose project label. It is not a second workload and does not prove the members can move together.", "field-note"));
          items.forEach((workload) => {
            groupedIds.add(workload.id);
            body.append(workloadRecord(workload));
          });
          if (!items.length) body.append(empty("No members match the current filters."));
          if (missing.length) body.append(node("h4", "Not found, by native ID"), list(missing, ""));
          section.append(disclosure(`application:${item.id}`, "Members", body, "record application-members"));
          ui.discovery.append(section);
        });
      }
      nativeGroups(workloads.filter((workload) => !groupedIds.has(workload.id)), workloadRecord, ui.discovery, applicationMode ? "Ungrouped on " : "");
      if (!ui.discovery.childElementCount) ui.discovery.append(empty(fleet.resources.length ? "No units or containers match these filters. Try All lifecycles." : "Nothing discovered yet. Check a host that has a collector."));
    });
  }
  function artifactRecord(artifact) {
    const body = node("div", undefined, "record-body");
    body.append(metadata([
      ["Artifact ID", text(artifact.id)], ["Host", hostName(artifact.host_id)], ["Runtime / scope", `${text(artifact.backend)} / ${text(artifact.scope)}`],
      ["Native ID", text(artifact.native_id)], ["Kind", text(artifact.kind)], ["Last checked", timestamp(artifact.observed_at)],
    ]), node("p", "Present at the last check. Not a running workload and not a health claim.", "field-note"),
    evidence(`artifact-evidence:${artifact.id}`, artifact.extensions || {}));
    const summary = group("span", "record-summary", node("span", text(artifact.name, artifact.native_id), "record-name"), node("span", text(artifact.kind), "badge"));
    summary.append(ageNode(artifact.observed_at, artifact.freshness, artifact.freshness_ttl_seconds, summary));
    return disclosure(`artifact:${artifact.id}`, summary, body);
  }
  function renderArtifacts() {
    if (!fleet) return;
    rerender(ui.artifacts, () => {
      const query = ui.workloadSearch.value.trim().toLocaleLowerCase();
      const artifacts = fleet.artifacts.filter((artifact) => inventoryMatches(artifact, query));
      ui.artifactCount.textContent = `${artifacts.length} of ${fleet.artifacts.length}`;
      ui.artifacts.replaceChildren();
      nativeGroups(artifacts, artifactRecord, ui.artifacts);
      if (!artifacts.length) ui.artifacts.append(empty(fleet.artifacts.length ? "No images or packages match these filters." : "No images or packages found. An empty list is not proof that nothing is installed."));
    });
  }
  function renderBackends() {
    ui.backends.replaceChildren();
    if (fleet.provenance) ui.backends.append(node("p", fleet.provenance, "section-note"));
    ui.backends.append(fleet.backends.length ? table(["Name", "ID", "Status", "Capabilities"], fleet.backends.map((backend) => [
      text(backend.name, backend.id), node("span", text(backend.id), "machine"), text(backend.status), strings(backend.capabilities).join(", ") || "None reported",
    ])) : empty("No collectors or backends reported."));
  }

  // --- Cold migration proposals ---
  function compatibility(workload, host) {
    if (!workload) return "Choose a workload first.";
    if (sourceId(workload) === host.id) return "Same as source; migration will be blocked.";
    const architectures = strings(workload.architectures);
    if (architectures.length && host.architecture && host.architecture !== "unknown" && !architectures.includes(host.architecture)) return "Declared architecture incompatible.";
    const missing = strings(workload.requirements).filter((requirement) => !declaredCapabilities(host).includes(requirement));
    if (missing.length) return `Missing declared capabilities: ${missing.join(", ")}.`;
    if (!architectures.length || !host.architecture || host.architecture === "unknown") return "Compatibility unknown; no verified architecture match.";
    return "Declarations match; runtime, artifacts and data compatibility remain unverified.";
  }
  function fillSelections() {
    const workloadId = ui.workload.value;
    const targetId = ui.target.value;
    ui.workload.replaceChildren(node("option", fleet.workloads.length ? "Select a workload" : "No workloads defined"));
    ui.workload.firstElementChild.value = "";
    // Cold migration applies to observed workloads; deployed instances move by undeploy and redeploy, and a
    // registered application belongs to its owner.
    fleet.workloads.filter((workload) => workload.management === "observed").forEach((workload) => {
      const option = node("option", `${text(workload.name, workload.id)}, on ${hostName(sourceId(workload))}`);
      option.value = workload.id;
      ui.workload.append(option);
    });
    if (fleet.workloads.some((workload) => workload.id === workloadId)) ui.workload.value = workloadId;
    ui.target.replaceChildren(node("option", "Select a destination"));
    ui.target.firstElementChild.value = "";
    fleet.hosts.forEach((host) => {
      const option = node("option", `${hostLabel(host)}: ${compatibility(selectedWorkload(), host)}`);
      option.value = host.id;
      ui.target.append(option);
    });
    if (fleet.hosts.some((host) => host.id === targetId)) ui.target.value = targetId;
    if ((workloadId && !ui.workload.value) || (targetId && !ui.target.value)) clearProposal("A selected item is no longer in the cache. Select it again before running the preflight.");
    if (!ui.workload.value) wizardStep = 1;
    else if (!ui.target.value && wizardStep === 3) wizardStep = 2;
    showStep(wizardStep, false);
  }
  function routeTrack(name, index, car, note) {
    const track = group("div", "track", node("span", name, "track-host"), group("div", "track-line", car), group("div", "track-end", node("span", note, "readout")));
    track.style.setProperty("--i", String(index));
    return track;
  }
  function renderRoute(workload, target) {
    ui.route.replaceChildren();
    if (!workload || !target) return;
    const name = text(workload.name, workload.id);
    const car = group("span", "car", lifecycleLamp(workload.lifecycle), node("span", name, "car-name"));
    if (sourceId(workload) === target.id) {
      ui.route.append(routeTrack(hostName(target.id), 0, car, "Source and destination are the same host"));
      return;
    }
    ui.route.append(routeTrack(hostName(sourceId(workload)), 0, car, "Source, stays until verified"),
      routeTrack(hostLabel(target), 1, group("span", "car is-ghost", lamp("dark"), node("span", name, "car-name")), "Proposed destination"));
    ui.route.setAttribute("aria-label", `Proposed move of ${name} from ${hostName(sourceId(workload))} to ${hostLabel(target)}`);
    ui.route.setAttribute("role", "img");
  }
  function renderContexts() {
    rememberDetails(ui.workloadContext);
    rememberDetails(ui.targetContext);
    rememberDetails(ui.reviewContext);
    const workload = selectedWorkload();
    const target = selectedTarget();
    ui.workloadContext.replaceChildren();
    if (workload) {
      ui.workloadContext.append(metadata([
        ["Source", hostName(sourceId(workload))], ["Purpose", text(workload.purpose)], ["Runtime", workloadRuntime(workload).label],
        ["Primary state", `${text(workload.lifecycle)}; application health ${text(workload.health, "unknown")}`],
        ["Migration recipe", workload.recipe ? "Supplied" : "Not supplied; the preflight will report a blocker"],
      ]));
      if (workload.observed_at) ui.workloadContext.append(ageNode(workload.observed_at, workload.freshness, workload.freshness_ttl_seconds));
    } else ui.workloadContext.append(empty(fleet.workloads.length ? "Choose a defined workload. A discovered unit or container cannot be migrated until you define it as a workload." : "No workloads are defined yet. Define one under Workloads, from Discovered on hosts."));
    ui.targetContext.replaceChildren();
    if (target) {
      ui.targetContext.append(node("p", compatibility(workload, target), "section-note"), ageNode(target.observation?.snapshot?.observed_at, target.observation?.freshness, target.observation?.freshness_ttl_seconds), resourceSummary(target.observation?.snapshot));
      ui.targetContext.append(node("p", "These are timestamped measurements, not reserved capacity.", "field-note"));
    } else ui.targetContext.append(empty("Every declared host is listed, including ones whose compatibility is unknown."));
    renderRoute(workload, target);
    ui.reviewContext.replaceChildren(metadata([
      ["Workload", workload ? text(workload.name, workload.id) : "Not selected"],
      ["Route", `${hostName(sourceId(workload))} to ${target ? hostLabel(target) : "not selected"}`],
      ["Downtime", "Stop, transfer, startup and verification; duration not yet estimated"],
      ["Recovery", workload?.recipe?.recovery || "No service-specific recovery instructions supplied"],
    ]));
    if (workload?.recipe) ui.reviewContext.append(disclosure("selected-recipe", "Service-specific recipe", node("pre", JSON.stringify(workload.recipe, null, 2), "evidence")));
  }
  function showStep(step, focus = true) {
    if ((step > 1 && !ui.workload.value) || (step > 2 && !ui.target.value)) return;
    wizardStep = step;
    for (let index = 1; index <= 3; index += 1) {
      byId(`wizard-${index}`).hidden = index !== step;
      const button = byId(`step-${index}`);
      if (index === step) button.setAttribute("aria-current", "step"); else button.removeAttribute("aria-current");
    }
    if (focus) byId(["", "workload-step-title", "destination-step-title", "review-step-title"][step]).focus();
  }
  function updateControls() {
    ui.reload.disabled = Boolean(request);
    ui.reload.textContent = request?.kind === "cache" ? "Reading…" : "Refresh";
    ui.hosts.setAttribute("aria-busy", String(request?.kind === "observe" || request?.kind === "cache"));
    ui.form.setAttribute("aria-busy", String(request?.kind === "plan"));
    ui.workload.disabled = !fleet || Boolean(request) || !fleet.workloads.length;
    ui.target.disabled = !fleet || Boolean(request) || !fleet.hosts.length;
    byId("next-destination").disabled = Boolean(request) || !ui.workload.value;
    byId("next-review").disabled = Boolean(request) || !ui.workload.value || !ui.target.value;
    byId("step-2").disabled = Boolean(request) || !ui.workload.value;
    byId("step-3").disabled = Boolean(request) || !ui.workload.value || !ui.target.value;
    ui.prepare.disabled = Boolean(request) || !ui.workload.value || !ui.target.value;
    ui.prepare.textContent = request?.kind === "plan" ? "Running…" : "Run preflight";
    document.querySelectorAll("[data-observe-host]").forEach((button) => {
      const host = fleet?.hosts.find((item) => item.id === button.dataset.observeHost);
      if (host) updateObserveButton(button, host);
    });
  }
  function clearProposal(message = "Run the preflight to see blockers, downtime and recovery.") {
    currentPlan = null;
    ui.proposal.replaceChildren(empty(message));
    ui.proposalStatus.textContent = "";
    error(ui.proposalError, "");
  }
  function renderProposal(plan) {
    const result = document.createDocumentFragment();
    rememberDetails(ui.proposal);
    const blockers = node("section", undefined, plan.blockers.length ? "blocker-box" : "blocker-box is-clear");
    blockers.append(node("h4", plan.blockers.length === 1 ? "1 blocker" : `${plan.blockers.length} blockers`), list(plan.blockers, "No blockers returned. That is not approval and does not prove readiness."));
    result.append(blockers, node("h4", "Downtime and warnings"), list(plan.warnings, "No downtime estimate or warnings returned."));
    result.append(node("h4", "Requirements"), list(plan.requirements, "No requirements returned."));
    result.append(node("h4", "Proposed steps"));
    const steps = node("ol", undefined, "proposal-steps");
    plan.steps.forEach((step) => {
      const item = node("li");
      item.append(node("strong", text(step.action)), node("p", text(step.detail)));
      steps.append(item);
    });
    result.append(plan.steps.length ? steps : empty("No service-specific steps available."));
    const recovery = plan.steps.filter((step) => step.action === "recovery").map((step) => text(step.detail));
    result.append(node("h4", "Recovery"), list(recovery, "No recovery steps supplied. A service-specific recovery plan is required."));
    const checks = node("div", undefined, "record-body");
    checks.append(node("p", "Supported means one checked precondition holds, not that the migration is ready. Declared values are not verified.", "field-note"));
    array(plan.checks).forEach((check) => {
      const body = node("div", undefined, "record-body check-detail");
      body.append(node("p", text(check.detail)), node("h4", "Declaration"),
        node("pre", JSON.stringify(check.declaration ?? null, null, 2), "evidence"),
        node("h4", "Observed"), node("pre", JSON.stringify(check.evidence ?? null, null, 2), "evidence"));
      body.querySelectorAll("pre").forEach((pre) => { pre.tabIndex = 0; });
      const summary = group("span", "record-summary", lamp(check.status === "supported" ? "run" : "fail"), node("span", text(check.id), "record-name"), node("span", sentence(text(check.status)), check.status === "supported" ? "record-state" : "record-state danger"));
      checks.append(disclosure(`plan-check:${check.id}`, summary, body));
    });
    if (!array(plan.checks).length) checks.append(empty("No recipe assessment checks returned; readiness remains unverified."));
    result.append(disclosure("plan-checks", `Individual checks, ${array(plan.checks).length}`, checks));
    result.append(metadata([
      ["Preflight ID", text(plan.id)], ["Workload ID", text(plan.workload_id)],
      ["Source", hostName(plan.source_id)], ["Destination", hostName(plan.target_id)], ["Executable", "No. This is an assessment only."],
    ]), evidence("plan-evidence", plan));
    ui.proposal.replaceChildren(result);
  }
  async function prepareProposal(event) {
    event.preventDefault();
    if (request || !selectedWorkload() || !selectedTarget() || wizardStep !== 3) return;
    pauseStream();
    request = { kind: "plan" };
    updateControls();
    error(ui.proposalError, "");
    ui.proposalStatus.textContent = "Running the preflight. Nothing on any host changes.";
    try {
      const plan = await api("/api/plans/migration", { workload_id: ui.workload.value, target_id: ui.target.value });
      if (plan.executable !== false || plan.status !== "proposal" || plan.kind !== "cold-migration"
        || ![plan.blockers, plan.warnings, plan.requirements].every((items) => Array.isArray(items) && items.every((item) => typeof item === "string"))
        || !Array.isArray(plan.steps) || !plan.steps.every((step) => step && typeof step === "object")
        || (plan.checks !== undefined && (!Array.isArray(plan.checks) || !plan.checks.every((check) => check && typeof check.id === "string" && ["supported", "blocked"].includes(check.status) && typeof check.detail === "string")))) throw new Error("Response did not match the non-executable proposal contract.");
      currentPlan = plan;
      renderProposal(plan);
      proposalSummary = `Preflight finished ${clock(Date.now())} with ${plan.blockers.length === 1 ? "1 blocker" : `${plan.blockers.length} blockers`}. Nothing was changed.`;
      ui.proposalStatus.textContent = proposalSummary;
    } catch (cause) {
      error(ui.proposalError, cause.message);
      ui.proposalStatus.textContent = currentPlan ? "The request failed. The earlier result below is unchanged." : "No result returned. The request was not retried.";
    } finally { request = null; updateControls(); startStream(); }
  }

  // --- Brokered operations ---
  function operationPolicy() {
    return fleet?.operation_policy?.enabled === true ? fleet.operation_policy : { enabled: false, shell_hosts: [], workloads: [] };
  }
  function managedWorkload(id) { return array(operationPolicy().workloads).find((item) => item.id === id); }
  function operationNeedsTarget(workload = managedWorkload(op.workload.value)) {
    return !workload?.inspection_required && ["deploy", "migrate"].includes(op.action.value);
  }
  function lifecycleInspection(id) {
    return fleet?.workloads.find((item) => item.id === id)?.lifecycle_inspection;
  }
  function inspectionFresh(record) {
    const observed = Date.parse(record?.inspected_at);
    return record?.fresh === true && Number.isFinite(observed) && Date.now() - observed < 120000;
  }
  function renderOperationInspection() {
    rememberDetails(op.inspection);
    op.inspection.replaceChildren();
    const workload = managedWorkload(op.workload.value);
    if (!workload?.inspection_required) return;
    const record = lifecycleInspection(workload.id);
    op.inspection.append(node("p", record
      ? `State at inspection: ${text(record.inspection?.lifecycle)}, ${timestamp(record.inspected_at)}. Application health is not verified.`
      : "Inspecting reads this workload's unit or container on its configured host. It does not start or change anything.",
    "section-note"));
    if (record) op.inspection.append(evidence(`operation-inspection:${workload.id}`, record, "Inspected identity, state and warnings"));
  }
  function sideDesk() {
    op.panel.hidden = fleet?.read_only_view === true || !operationsOpen || !array(operationPolicy().workloads).length;
  }
  function openOperation(id, action = null) {
    selectTab("workloads");
    operationsOpen = true;
    sideDesk();
    op.workload.value = id;
    fillOperationChoices();
    if (action) op.action.value = action;
    clearOperationPlan();
    renderWorkloads();
    op.panel.scrollIntoView({ block: "nearest" });
    op.action.focus({ preventScroll: true });
  }
  function setOptions(select, choices, placeholder) {
    const selected = new Set(Array.from(select.selectedOptions, (option) => option.value));
    const options = choices.map(([value, label]) => {
      const option = node("option", label);
      option.value = value;
      option.selected = selected.has(value);
      return option;
    });
    if (placeholder) {
      const option = node("option", placeholder);
      option.value = "";
      options.unshift(option);
    }
    select.replaceChildren(...options);
  }
  function fillOperationChoices() {
    const workload = managedWorkload(op.workload.value);
    setOptions(op.action, strings(workload?.actions).map((action) => [action, sentence(action)]));
    setOptions(op.target, strings(workload?.allowed_hosts).map((id) => [id, hostName(id)]), "Use current placement");
    if (!operationNeedsTarget(workload)) op.target.value = "";
    renderOperationInspection();
  }
  function clearOperationPlan() {
    operationPlan = null;
    operationAttempted = false;
    op.approval.checked = false;
    op.plan.replaceChildren();
    byId("operation-approval").hidden = true;
    op.status.textContent = "";
    error(op.error, "");
    operationControls();
  }
  function gate(id, state, detail) {
    const item = byId(`gate-${id}`);
    item.dataset.state = state;
    item.querySelector(".gate-state").textContent = detail;
  }
  function operationControls() {
    const workload = managedWorkload(op.workload.value);
    const record = lifecycleInspection(op.workload.value);
    const fresh = inspectionFresh(record);
    const requiresInspection = workload?.inspection_required === true;
    const actionAvailable = !requiresInspection || (fresh && strings(record.inspection?.supported_actions).includes(op.action.value));
    const changed = operationPlan?.inspection_fingerprint && operationPlan.inspection_fingerprint !== record?.inspection_fingerprint;
    op.inspect.hidden = !requiresInspection;
    op.inspect.disabled = operationPending || !workload;
    const needsTarget = operationNeedsTarget(workload);
    byId("operation-target-label").hidden = !needsTarget;
    if (!needsTarget) op.target.value = "";
    byId("plan-operation").disabled = operationPending || !workload || !actionAvailable;
    [op.workload, op.action, op.target].forEach((select) => { select.disabled = operationPending; });
    if (operationPlan && !operationAttempted && requiresInspection && (!fresh || changed)) {
      op.approval.checked = false;
      op.status.textContent = changed ? "The inspection changed. The plan below is kept for reference; prepare a new one before executing."
        : "The inspection expired. Inspect again and prepare a new plan. Nothing runs on its own.";
    }
    const planLive = Boolean(operationPlan) && Date.parse(operationPlan.expires_at) > Date.now();
    const planBlocked = operationPlan?.executable === false;
    const planUsable = planLive && !planBlocked && !(requiresInspection && (!fresh || Boolean(changed)));
    op.execute.disabled = operationPending || operationAttempted || !planUsable || !op.approval.checked || !op.requestId.value.trim();
    // The interlock restates the same conditions that disable the buttons, so a locked gate always says why.
    if (!workload) gate("inspect", "locked", "No workload selected");
    else if (!requiresInspection) gate("inspect", "skip", "Not required for this recipe");
    else if (fresh) gate("inspect", "done", `Fresh until ${clock(Date.parse(record.inspected_at) + 120000)}`);
    else gate("inspect", record ? "warn" : "open", record ? "Expired, inspect again" : "Needed before planning");
    if (operationAttempted) gate("plan", "done", "Used");
    else if (operationPlan) gate("plan", planUsable ? "done" : "warn", planUsable ? `Prepared, expires ${clock(operationPlan.expires_at)}`
      : planBlocked ? "Blocked; see plan" : !planLive ? "Expired, prepare again" : changed ? "Inspection changed, prepare again" : "Inspection expired");
    else if (!workload || !actionAvailable) gate("plan", "locked", requiresInspection && !fresh ? "Inspect first" : workload ? "Action unavailable in this state" : "No workload selected");
    else gate("plan", "open", "Ready to prepare");
    if (operationAttempted) gate("approve", "done", "Approved");
    else if (!planUsable) gate("approve", "locked", planBlocked ? "Plan blocked" : "Needs a current plan");
    else gate("approve", op.approval.checked ? "done" : "open", op.approval.checked ? "Approved" : "Tick the box to approve");
    if (operationAttempted) gate("execute", operationPending ? "open" : "done", operationPending ? "Running" : "Sent, see the audit log");
    else if (!planUsable || !op.approval.checked) gate("execute", "locked", "Needs approval");
    else gate("execute", op.requestId.value.trim() ? "open" : "locked", op.requestId.value.trim() ? "Ready" : "Needs a request ID");
    byId("run-shell").disabled = operationPending || !strings(operationPolicy().shell_hosts).includes(op.shellHost.value);
    byId("shell-new-request").disabled = operationPending;
  }
  function renderOperations() {
    const policy = operationPolicy();
    const workloads = array(policy.workloads);
    const shellHosts = strings(policy.shell_hosts);
    byId("open-workload-operations").hidden = !workloads.some((item) => strings(item.actions).includes("migrate"));
    op.shellPanel.hidden = !shellHosts.length;
    const enabled = workloads.length || shellHosts.length || strings(policy.fleet_key_hosts).length;
    const mode = byId("mode-label");
    const viewOnly = fleet?.read_only_view === true;
    mode.textContent = viewOnly ? "Read-only view" : enabled ? "Control enabled" : "Monitoring only";
    mode.classList.toggle("is-flagged", Boolean(enabled) && !viewOnly);
    mode.title = viewOnly ? "This address only shows the desk. Actions are available on the control host itself, at http://127.0.0.1:8710."
      : enabled ? "Control operations are configured. Each runs only when you request and approve it." : "Monitoring and migration preflight only. No control operations are configured.";
    byId("footer-mode").textContent = viewOnly ? "Read-only view of cached data. Actions are available on the control host itself."
      : enabled ? "Shows cached data. Operations run only when you request and approve them." : "Shows cached data. No control operations are configured.";
    const signature = JSON.stringify(policy);
    if (signature !== policySignature) {
      policySignature = signature;
      setOptions(op.workload, workloads.map((item) => [item.id, text(item.name, item.id)]));
      fillOperationChoices();
      setOptions(op.shellHost, shellHosts.map((id) => [id, hostName(id)]));
      const hosts = [...new Set([...shellHosts, ...workloads.flatMap((item) => strings(item.allowed_hosts))])];
      setOptions(op.extra, hosts.map((id) => [id, hostName(id)]));
      // Fleet updates may change policy while an operation finishes. Keep its plan, outcome and audit reference.
      if (!operationPending && !operationAttempted) clearOperationPlan();
    }
    sideDesk();
    renderReceipts(array(fleet?.operations));
    renderOperationInspection();
    operationControls();
  }
  const RECEIPT_ASPECTS = { succeeded: "run", failed: "fail", busy: "transit", partial: "transit", pending: "transit", "needs-inspection": "transit" };
  function renderReceipts(all) {
    rerender(op.receipts, () => {
      byId("operation-count").textContent = all.length ? String(all.length) : "";
      const unsettled = all.filter((receipt) => receipt.status === "needs-inspection").length;
      const receipts = byId("receipt-filter").value === "all" ? all : all.filter((receipt) => receipt.status !== "succeeded");
      byId("receipt-summary").textContent = `${receipts.length === all.length ? "" : `${receipts.length} shown of `}${all.length} ${all.length === 1 ? "entry" : "entries"}${unsettled ? `, ${unsettled} need inspection` : ""}`;
      op.receipts.previousElementSibling.hidden = !receipts.length;
      op.receipts.replaceChildren(...receipts.map((receipt) => {
        const previous = receiptDetails.get(receipt.id);
        if (previous && (previous.status !== receipt.status || previous.finished_at !== receipt.finished_at)) receiptDetails.delete(receipt.id);
        const body = node("div", undefined, "record-body");
        const cached = receiptDetails.get(receipt.id);
        // Shell entries record the script that ran: show it as readable text above the raw entry.
        const commandLabel = node("h4", "Command that ran");
        const command = node("pre", "", "evidence");
        const entry = node("pre", "Loading the full entry…", "evidence");
        command.tabIndex = 0;
        entry.tabIndex = 0;
        const showEntry = (result) => {
          const { script, ...rest } = result;
          const redacted = result.script_redacted === true;
          commandLabel.hidden = command.hidden = typeof script !== "string" && !redacted;
          command.textContent = redacted ? "Not shown in this view. Read it on the desk itself." : text(script, "");
          entry.textContent = JSON.stringify(rest, null, 2);
        };
        commandLabel.hidden = command.hidden = true;
        if (cached) showEntry(cached);
        body.append(commandLabel, command, entry);
        const status = text(receipt.status);
        const what = group("span", "receipt-what", node("strong", sentence(text(receipt.action, text(receipt.kind)))),
          typeof receipt.workload_id === "string" && node("span", receipt.workload_id, "machine"),
          typeof receipt.playbook_id === "string" && node("span", receipt.playbook_id, "machine"),
          typeof receipt.action === "string" && receipt.action !== receipt.kind && node("span", text(receipt.kind), "row-sub"),
          typeof receipt.script_preview === "string" && node("span", receipt.script_preview, "machine"));
        const summary = group("span", "receipt-summary",
          group("span", status === "failed" ? "receipt-outcome danger" : "receipt-outcome", lamp(RECEIPT_ASPECTS[status] || "dark", sentence(status)), node("span", sentence(status))),
          what, node("span", strings(receipt.host_ids).map(hostName).join(", ") || "No host recorded", "receipt-hosts"),
          node("span", timestamp(receipt.started_at), "receipt-time"), node("span", text(receipt.id), "machine receipt-id"),
          typeof receipt.error === "string" && receipt.error ? node("span", receipt.error, "row-attention")
            : number(receipt.exit_code) && receipt.exit_code !== 0 ? node("span", `Exit code ${receipt.exit_code}`, "row-attention") : null);
        const details = disclosure(`operation:${receipt.id}`, summary, body, "row-details receipt-row");
        const readReceipt = async () => {
          if (!details.open || receiptDetails.has(receipt.id) || details.dataset.loading) return;
          details.dataset.loading = "true";
          try {
            const result = await api(`/api/operations/${encodeURIComponent(receipt.id)}`);
            receiptDetails.set(receipt.id, result);
            showEntry(result);
          } catch (cause) { entry.textContent = cause.message; }
          finally { delete details.dataset.loading; }
        };
        details.addEventListener("toggle", readReceipt);
        if (details.open) readReceipt();
        return details;
      }));
      if (!receipts.length) op.receipts.append(empty(all.length ? "Every recorded operation succeeded. Choose All outcomes to see them."
        : operationPolicy().enabled ? "No operations yet. Every inspection, executed plan, shell run and key change is recorded here." : "Nothing recorded. No control operations are configured."));
    });
  }
  async function refreshReceipts() {
    const button = byId("refresh-operations");
    button.disabled = true;
    error(byId("receipts-error"), "");
    try {
      const receipts = await api("/api/operations");
      if (!Array.isArray(receipts)) throw new Error("Unexpected receipt history response.");
      receiptDetails.clear();
      if (fleet) fleet.operations = receipts;
      renderReceipts(receipts);
    } catch (cause) { error(byId("receipts-error"), cause.message); }
    finally { button.disabled = false; }
  }
  async function inspectManagedWorkload() {
    if (op.inspect.disabled || !managedWorkload(op.workload.value)?.inspection_required) return;
    const workloadId = op.workload.value;
    const requestId = crypto.randomUUID();
    clearOperationPlan();
    operationPending = true;
    operationControls();
    op.status.textContent = `Inspecting, read-only. Request ${requestId}. No lifecycle action is taken.`;
    try {
      const result = await api("/api/operations/inspect", {workload_id: workloadId, request_id: requestId}, 300000);
      op.status.textContent = `Inspection ${text(result.receipt?.id)}: ${text(result.receipt?.status)}. Check the native identity and state before planning.`;
      error(op.error, typeof result.receipt?.error === "string" ? result.receipt.error : "");
      await loadFleet();
    } catch (cause) {
      error(op.error, cause.message);
      op.status.textContent = `Inspection outcome not confirmed for ${requestId}. Check the audit log. It was not retried.`;
    } finally { operationPending = false; operationControls(); }
  }
  async function prepareOperation(event) {
    event.preventDefault();
    if (byId("plan-operation").disabled) return;
    clearOperationPlan();
    operationPending = true;
    operationControls();
    op.status.textContent = "Preparing the plan. No workload will change.";
    try {
      const payload = { action: op.action.value, workload_id: op.workload.value };
      if (operationNeedsTarget() && op.target.value) payload.target_id = op.target.value;
      const plan = await api("/api/operations/plan", payload);
      if (typeof plan.id !== "string" || plan.approval_required !== true || !Number.isFinite(Date.parse(plan.expires_at))
        || ![plan.steps, plan.warnings].every((items) => Array.isArray(items) && items.every((item) => typeof item === "string"))
        || (plan.blockers !== undefined && !(Array.isArray(plan.blockers) && plan.blockers.every((item) => typeof item === "string")))) {
        throw new Error("Response did not match the exact operation-plan contract.");
      }
      operationPlan = plan;
      op.plan.append(metadata([["Action", plan.action], ["Workload", plan.workload_id],
        ...(["deploy", "migrate"].includes(plan.action)
          ? [["Source", hostName(plan.source_id)], ["Target", hostName(plan.target_id)]]
          : [["Host", hostName(plan.source_id || plan.target_id)]]),
        ["Expires", timestamp(plan.expires_at)]]));
      if (plan.executable === false) op.plan.append(node("h4", "Blocked"), list(strings(plan.blockers), "This plan cannot be executed."));
      op.plan.append(node("h4", "Steps"), list(plan.steps, "No steps supplied."), node("h4", "Warnings"),
        list(plan.warnings, "No warnings supplied."), evidence("operation-plan-evidence", plan, "Full plan (JSON)"));
      op.requestId.value = crypto.randomUUID();
      byId("operation-approval").hidden = plan.executable === false;
      op.status.textContent = plan.executable === false ? "Plan blocked. Review the reasons below. Nothing can be executed."
        : "Plan prepared. Read it, then approve it to execute.";
    } catch (cause) { error(op.error, cause.message); op.status.textContent = "No plan was prepared. Nothing was executed."; }
    finally { operationPending = false; operationControls(); }
  }
  async function executeOperation() {
    if (op.execute.disabled || !operationPlan) return;
    operationPending = true;
    operationAttempted = true;
    operationControls();
    error(op.error, "");
    const requestId = op.requestId.value.trim();
    op.status.textContent = `Executing the approved plan. Request ${requestId}. It will not be retried.`;
    try {
      const timeoutSeconds = number(operationPlan.execution_timeout_seconds) && operationPlan.execution_timeout_seconds > 0
        ? Math.min(operationPlan.execution_timeout_seconds, 600) : 300;
      const result = await api("/api/operations/execute", { plan_id: operationPlan.id, approved: true, request_id: requestId }, timeoutSeconds * 1000);
      op.status.textContent = `Operation ${text(result.receipt?.id)}: ${text(result.receipt?.status)}${result.replayed ? " (already recorded; not executed again)" : ""}. Details are in the audit log.`;
      error(op.error, typeof result.receipt?.error === "string" ? result.receipt.error : "");
      if (result.stdout || result.stderr) op.plan.append(evidence("operation-command-output",
        { stdout: result.stdout ?? "", stderr: result.stderr ?? "" }, "Command output (not retained)"));
      await loadFleet();
    } catch (cause) {
      error(op.error, cause.message);
      op.status.textContent = `Outcome not confirmed for request ${requestId}. Check the audit log before preparing another execution.`;
    } finally { operationPending = false; operationControls(); await refreshReceipts(); }
  }
  async function runShell(event) {
    event.preventDefault();
    if (operationPending || byId("run-shell").disabled) return;
    error(op.shellError, "");
    if (new TextEncoder().encode(op.script.value).length > 16384) {
      error(op.shellError, "The script is larger than 16 KiB. Shorten it or run it from a file on the host.");
      return;
    }
    if (!op.shellId.value.trim()) op.shellId.value = crypto.randomUUID();
    const requestId = op.shellId.value.trim();
    const payload = { host_id: op.shellHost.value, script: op.script.value, request_id: requestId,
      timeout_seconds: Number(op.timeout.value), extra_host_ids: Array.from(op.extra.selectedOptions, (option) => option.value) };
    operationPending = true;
    operationControls();
    op.output.textContent = "";
    op.output.hidden = true;
    op.shellStatus.textContent = `Running the script. Request ${requestId}. It will not be retried.`;
    try {
      const result = await api("/api/operations/shell", payload, 300000);
      op.shellStatus.textContent = `Operation ${text(result.receipt?.id)}: ${text(result.receipt?.status)}${result.replayed ? " (existing receipt; output is not recovered)" : ""}.`;
      op.output.textContent = `${typeof result.stdout === "string" ? result.stdout : ""}${typeof result.stderr === "string" && result.stderr ? `\n[stderr]\n${result.stderr}` : ""}`;
      op.output.hidden = !op.output.textContent;
    } catch (cause) {
      error(op.shellError, cause.message);
      op.shellStatus.textContent = `Outcome not confirmed for request ${requestId}. Check the audit log before running it again.`;
    } finally { operationPending = false; operationControls(); await refreshReceipts(); }
  }

  // --- Fleet SSH keys ---
  function keyState() {
    return fleet?.fleet_keys || { enabled: false, allowed_hosts: [], members: [], hosts: [], connections: [], revision: "" };
  }
  function selectedKeyHosts() { return Array.from(keys.hosts.selectedOptions, (option) => option.value); }
  function keyControls() {
    const state = keyState();
    const enabled = state.enabled === true;
    const pending = keyPending || operationPending;
    keys.hosts.disabled = pending || !enabled;
    keys.action.disabled = pending || !enabled;
    byId("inspect-fleet-keys").disabled = pending || !enabled || !selectedKeyHosts().length;
    byId("plan-fleet-keys").disabled = pending || !enabled || (!selectedKeyHosts().length && keys.action.value !== "reconcile");
    byId("execute-fleet-keys").disabled = pending || !enabled || !keyPlan || keyAttempted || !keys.approval.checked
      || !keys.requestId.value.trim() || Date.parse(keyPlan.expires_at) <= Date.now() || keyPlanRevision !== state.revision;
  }
  function clearKeyPlan() {
    keyPlan = null;
    keyAttempted = false;
    keys.approval.checked = false;
    keys.plan.replaceChildren();
    byId("fleet-key-approval").hidden = true;
    keys.status.textContent = "";
    error(keys.error, "");
    keyControls();
  }
  function connectionLabel(source, target, connection) {
    if (source === target) return ["skip", "Self"];
    if (connection?.desired === false && connection.status === "verified") return ["halt", "Revoked"];
    const status = text(connection?.status, "unknown");
    return [status === "verified" ? "run" : status === "unknown" ? "dark" : "transit", sentence(status)];
  }
  function renderFleetKeys() {
    const state = keyState();
    const members = strings(state.members);
    byId("fleet-keys-summary").textContent = `${members.length} ${members.length === 1 ? "member" : "members"}${state.enabled ? "" : ", changes disabled"}`;
    const hostStatus = byId("fleet-keys-status");
    hostStatus.replaceChildren();
    if (!state.enabled) hostStatus.append(node("p", "Fleet key management is not configured, so nothing here can inspect or change SSH. Cached data stays visible.", "section-note caution"));
    hostStatus.append(array(state.hosts).length ? table(["Host", "Membership", "Status", "Public fingerprint", "Detail"], array(state.hosts).map((host) => {
      const status = text(host.status, "unknown");
      return [hostName(host.host_id), members.includes(host.host_id) ? "Member" : "Not enrolled",
        group("span", "cell-state", lamp(status === "verified" ? "run" : status === "unknown" ? "dark" : "transit"), sentence(status)),
        node("span", text(host.fingerprint, "Not inspected"), "machine"), text(host.detail, "No detail supplied.")];
    })) : empty("No key inspection is cached. Select hosts below and inspect them to learn whether they can enroll."));
    const ids = [...new Set([...members, ...strings(state.allowed_hosts), ...array(state.hosts).map((host) => host.host_id)])].filter((id) => typeof id === "string");
    const matrix = node("table", undefined, "data-table connection-matrix");
    const heading = node("tr");
    const corner = node("th", "From / to"); corner.scope = "col"; heading.append(corner);
    ids.forEach((id) => { const cell = node("th", hostName(id)); cell.scope = "col"; heading.append(cell); });
    const body = node("tbody");
    const attention = [];
    ids.forEach((source) => {
      const row = node("tr");
      const label = node("th", hostName(source)); label.scope = "row"; row.append(label);
      ids.forEach((target) => {
        const connection = array(state.connections).find((item) => item.source_id === source && item.target_id === target);
        const [aspect, word] = connectionLabel(source, target, connection);
        const cell = node("td");
        if (aspect === "skip") cell.append(node("span", "Self", "matrix-self"));
        else {
          // A host that never enrolled is expected to be unreachable; only a member pair or a recorded attempt is worth flagging.
          const expected = connection || (members.includes(source) && members.includes(target));
          cell.append(group("span", aspect === "run" ? "cell-state" : expected ? "cell-state caution" : "cell-state matrix-self", lamp(aspect), expected || aspect === "run" ? word : "Not enrolled"));
          cell.title = [text(connection?.detail, "No detail"), connection?.verified_at ? `Observed ${timestamp(connection.verified_at)}` : ""].filter(Boolean).join(". ");
          if (aspect !== "run" && expected) attention.push(`${hostName(source)} to ${hostName(target)}: ${word.toLocaleLowerCase()}. ${text(connection?.detail, "No detail recorded.")}`);
        }
        row.append(cell);
      });
      body.append(row);
    });
    matrix.append(node("caption", "Peer SSH authentication, cached"), group("thead", "", heading), body);
    byId("fleet-keys-matrix").replaceChildren(ids.length ? matrix : empty("No peer connections known."));
    byId("fleet-keys-attention").replaceChildren(...(attention.length ? [node("h4", `${attention.length} not verified`), list(attention, "")] : []));
    const allowed = strings(state.allowed_hosts);
    const signature = JSON.stringify(allowed);
    if (signature !== keyHostSignature) {
      keyHostSignature = signature;
      setOptions(keys.hosts, allowed.map((id) => [id, hostName(id)]));
    }
    if (keyPlan && !keyAttempted && keyPlanRevision !== state.revision) {
      keys.approval.checked = false;
      keys.status.textContent = "Key data changed. The plan below is kept for reference; prepare and review a new one before executing.";
    }
    keyControls();
  }
  async function inspectFleetKeys() {
    if (byId("inspect-fleet-keys").disabled) return;
    const hostIds = selectedKeyHosts();
    const requestId = crypto.randomUUID();
    clearKeyPlan();
    keyPending = true;
    keyControls();
    keys.status.textContent = `Inspecting public SSH metadata, read-only. Request ${requestId}. No key is created and no host is enrolled.`;
    try {
      const result = await api("/api/fleet-keys/inspect", { host_ids: hostIds, request_id: requestId }, 300000);
      keys.status.textContent = `Inspection ${text(result.receipt?.id)}: ${text(result.receipt?.status)}. The table above and the audit log have the details.`;
      if (fleet) { fleet.fleet_keys = await api("/api/fleet-keys"); renderFleetKeys(); }
    } catch (cause) {
      error(keys.error, cause.message);
      keys.status.textContent = `Inspection outcome not confirmed for request ${requestId}. Check the audit log. It was not retried.`;
    } finally { keyPending = false; keyControls(); await refreshReceipts(); }
  }
  async function prepareFleetKeys(event) {
    event.preventDefault();
    if (byId("plan-fleet-keys").disabled) return;
    clearKeyPlan();
    keyPending = true;
    keyControls();
    keys.status.textContent = "Preparing a key plan from the cached inspection. No host changes.";
    try {
      const plan = await api("/api/fleet-keys/plan", { action: keys.action.value, host_ids: selectedKeyHosts() });
      if (typeof plan.id !== "string" || plan.approval_required !== true || !Number.isFinite(Date.parse(plan.expires_at))
        || ![plan.steps, plan.warnings, plan.host_ids].every((items) => Array.isArray(items) && items.every((item) => typeof item === "string"))) {
        throw new Error("Response did not match the exact fleet-key plan contract.");
      }
      keyPlan = plan;
      keyPlanRevision = keyState().revision;
      keys.plan.append(metadata([["Action", plan.action], ["Hosts", plan.host_ids.map(hostName).join(", ") || "Current members"], ["Expires", timestamp(plan.expires_at)]]),
        node("h4", "Steps"), list(plan.steps, "No steps supplied."), node("h4", "Warnings"), list(plan.warnings, "No warnings supplied."),
        evidence("fleet-key-plan-evidence", plan, "Full key plan (JSON)"));
      keys.requestId.value = crypto.randomUUID();
      byId("fleet-key-approval").hidden = false;
      keys.status.textContent = "Plan prepared. Read the partial and offline warnings, then approve this exact change.";
    } catch (cause) { error(keys.error, cause.message); keys.status.textContent = "No key plan was prepared. Nothing changed."; }
    finally { keyPending = false; keyControls(); }
  }
  async function executeFleetKeys() {
    if (byId("execute-fleet-keys").disabled || !keyPlan) return;
    keyAttempted = true;
    keyPending = true;
    keyControls();
    error(keys.error, "");
    const requestId = keys.requestId.value.trim();
    keys.status.textContent = `Applying the approved key plan. Request ${requestId}. It will not be retried.`;
    try {
      const result = await api("/api/fleet-keys/execute", { plan_id: keyPlan.id, approved: true, request_id: requestId }, 300000);
      keys.status.textContent = `Key operation ${text(result.receipt?.id)}: ${text(result.receipt?.status)}${result.replayed ? " (already recorded)" : ""}. Check the audit log for partial results; offline peers are not verified.`;
      error(keys.error, typeof result.receipt?.error === "string" ? result.receipt.error : "");
      if (fleet) { fleet.fleet_keys = await api("/api/fleet-keys"); renderFleetKeys(); }
    } catch (cause) {
      error(keys.error, cause.message);
      keys.status.textContent = `Outcome not confirmed for request ${requestId}. Check the audit log before another execution.`;
    } finally { keyPending = false; keyControls(); await refreshReceipts(); }
  }

  // Host forms live outside the rebuilt list: cached updates never replace a draft.
  function hostConnectionEditable(record) {
    return record.collector?.transport === "ssh";
  }
  function hostChanges() {
    if (!hostDraft) return {};
    const original = hostDraft.original;
    const values = {
      name: hostFields.name.value.trim(), platform: hostFields.platform.value.trim(),
      architecture: hostFields.architecture.value.trim(), notes: hostFields.notes.value,
      capabilities: hostFields.capabilities.value.split(",").map((value) => value.trim()).filter(Boolean),
    };
    const changes = {};
    Object.entries(values).forEach(([key, value]) => {
      if (JSON.stringify(value) !== JSON.stringify(original[key])) changes[key] = value;
    });
    if (hostConnectionEditable(original)) {
      const connection = { target: `${hostFields.account.value.trim()}@${hostFields.address.value.trim()}`,
        port: Number(hostFields.port.value), expected_hostname: hostFields.expected_hostname.value.trim() };
      Object.entries(connection).forEach(([key, value]) => {
        if (value !== (key === "port" ? original.collector.port || 22 : original.collector[key])) changes[key] = value;
      });
    }
    return changes;
  }
  function clearHostScan() {
    hostScan = null;
    hostEditor.confirm.checked = false;
    hostEditor.scan.replaceChildren();
    byId("host-key-confirmation").hidden = true;
  }
  function hostEditorControls() {
    const stale = hostReviewed && fleet?.registry_revision && hostReviewed.fleetRevision !== fleet.registry_revision
      && hostReviewed.revision !== fleet.registry_revision;
    hostEditor.save.disabled = hostPending || !hostReviewed || Boolean(stale);
    byId("review-host").disabled = hostPending || !hostDraft;
    byId("close-host-editor").disabled = hostPending;
    Object.values(hostFields).forEach((field) => { field.disabled = hostPending || !hostDraft; });
    hostEditor.connection.disabled = hostPending || !hostDraft || !hostConnectionEditable(hostDraft.original);
    const connectionDirty = ["target", "port", "expected_hostname"].some((key) => key in hostChanges());
    byId("scan-host-key").disabled = hostPending || hostDraft?.original.collector?.transport !== "ssh" || connectionDirty;
    const scanStale = hostScan && fleet?.registry_revision && hostScan.fleetRevision !== fleet.registry_revision && hostScan.revision !== fleet.registry_revision;
    byId("pin-host-key").disabled = hostPending || !hostScan || !hostEditor.confirm.checked || Boolean(scanStale)
      || Date.parse(hostScan?.expires_at) <= Date.now();
    if (stale) hostEditor.status.textContent = "The host registry changed. Your draft is kept. Review current hosts before saving; nothing is overwritten.";
    if (scanStale) hostEditor.status.textContent = "The host registry changed after this scan. Your draft is kept. Check the saved host key again before confirming.";
    else if (hostScan && Date.parse(hostScan.expires_at) <= Date.now()) hostEditor.status.textContent = "This host-key scan expired. Check the saved endpoint again before confirming.";
  }
  function showHostPins(record) {
    hostEditor.pins.replaceChildren(metadata([
      ["Verification", hostVerification(record)],
      ["Pinned fingerprints", array(record.pins).map((pin) => pin.fingerprint).join("\n") || "None"],
    ]));
    byId("host-key-note").textContent = record.collector?.transport === "ssh"
      ? "A scan does not establish trust. Save connection changes first, then check the saved endpoint and verify its fingerprints independently before pinning."
      : "Host-key scanning is only available for SSH collectors.";
  }
  function fillHostFields(record) {
    ["name", "platform", "architecture", "notes"].forEach((key) => { hostFields[key].value = record[key] || ""; });
    hostFields.capabilities.value = strings(record.capabilities).join(", ");
    const target = record.collector?.target || "";
    const split = target.lastIndexOf("@");
    hostFields.account.value = split < 0 ? "" : target.slice(0, split);
    hostFields.address.value = split < 0 ? target : target.slice(split + 1);
    hostFields.port.value = record.collector?.port || 22;
    hostFields.expected_hostname.value = record.collector?.expected_hostname || "";
  }
  async function openHostEditor(hostId) {
    if (hostPending) return;
    selectTab("hosts");
    hostEditor.panel.hidden = false;
    if (hostDraft) {
      hostEditor.status.textContent = "Your existing draft is kept. Finish it or close the editor before editing another host.";
      hostEditor.panel.scrollIntoView({ block: "nearest" });
      return;
    }
    hostPending = true;
    hostEditorControls();
    error(hostEditor.error, "");
    try {
      const registry = await api("/api/hosts");
      const record = array(registry.hosts).find((item) => item.id === hostId);
      if (!record) throw new Error("That host no longer exists. Refresh the host list.");
      hostDraft = { original: record, revision: registry.revision };
      hostReviewed = null;
      clearHostScan();
      fillHostFields(record);
      byId("host-editor-title").textContent = `Edit ${hostName(record.id)}`;
      byId("host-connection-note").textContent = hostConnectionEditable(record)
        ? "Changing the endpoint keeps the host-ID pin. A different host key will be refused."
        : "Connection edits are disabled for local, ADB and declaration-only hosts.";
      showHostPins(record);
      hostEditor.review.replaceChildren();
      hostEditor.status.textContent = "Edit the fields, then review the current registry before saving. No check runs automatically.";
    } catch (cause) { error(hostEditor.error, cause.message); }
    finally {
      hostPending = false;
      hostEditorControls();
      hostEditor.panel.scrollIntoView({ block: "nearest" });
      if (hostDraft) hostFields.name.focus({ preventScroll: true });
    }
  }
  async function reviewHost(event) {
    event.preventDefault();
    if (!hostDraft || hostPending) return;
    const changes = hostChanges();
    hostReviewed = null;
    hostPending = true;
    hostEditorControls();
    error(hostEditor.error, "");
    try {
      if (!Object.keys(changes).length) throw new Error("No changes to save.");
      const registry = await api("/api/hosts");
      const current = array(registry.hosts).find((item) => item.id === hostDraft.original.id);
      if (!current) throw new Error("That host no longer exists; the draft cannot recreate it.");
      const connection = ["target", "port", "expected_hostname"].some((key) => key in changes);
      if (connection && !hostConnectionEditable(current)) throw new Error("This host's connection is no longer editable. Your draft is kept.");
      hostReviewed = { changes, connection, revision: registry.revision, fleetRevision: fleet?.registry_revision };
      hostEditor.review.replaceChildren(metadata([["Registry revision", registry.revision],
        ["Effect", connection ? "Connection changes remain unverified until successful collection. Pinned identity is unchanged." : "Descriptive metadata only."]]),
      evidence("host-current-review", current, "Current saved host"), evidence("host-changes-review", changes, "Exact changes to save"));
      showHostPins(current);
      hostEditor.status.textContent = "Review the current saved host and these changes. Save applies only the listed fields at this exact revision.";
    } catch (cause) { error(hostEditor.error, cause.message); hostEditor.status.textContent = "Review failed. Your draft is kept."; }
    finally { hostPending = false; hostEditorControls(); }
  }
  async function saveHost() {
    if (hostPending || !hostReviewed || hostEditor.save.disabled) return;
    hostPending = true;
    hostEditorControls();
    error(hostEditor.error, "");
    try {
      const result = await api("/api/hosts/update", { host_id: hostDraft.original.id, changes: hostReviewed.changes,
        connection: hostReviewed.connection, expected_revision: hostReviewed.revision }, 300000);
      hostDraft.original = result.host;
      hostDraft.revision = result.revision;
      fillHostFields(result.host);
      hostReviewed = null;
      clearHostScan();
      showHostPins(result.host);
      hostEditor.review.replaceChildren();
      hostEditor.status.textContent = "Host saved. No host was contacted. Use Check now to verify a changed connection.";
      await loadFleet();
    } catch (cause) {
      hostReviewed = null;
      error(hostEditor.error, cause.message);
      hostEditor.status.textContent = "Save not confirmed. Your draft is kept. Review current hosts again; nothing is overwritten or retried.";
    } finally { hostPending = false; hostEditorControls(); }
  }
  async function scanHostKey() {
    if (!hostDraft || byId("scan-host-key").disabled) return;
    hostPending = true;
    clearHostScan();
    hostEditorControls();
    error(hostEditor.error, "");
    hostEditor.status.textContent = "Checking the saved SSH endpoint under its device lease. No key is trusted yet.";
    try {
      const registry = await api("/api/hosts");
      const current = array(registry.hosts).find((item) => item.id === hostDraft.original.id);
      if (!current) throw new Error("Host no longer exists.");
      const scan = await api("/api/hosts/scan-key", { host_id: current.id, request_id: crypto.randomUUID() }, 300000);
      hostScan = { ...scan, revision: registry.revision, fleetRevision: fleet?.registry_revision };
      hostEditor.scan.replaceChildren(metadata([
        ["Scanned endpoint", `${text(current.collector?.target)}:${current.collector?.port || 22}`],
        ["Currently pinned", array(current.pins).map((pin) => pin.fingerprint).join("\n") || "None"],
        ["Scanned fingerprints", strings(scan.fingerprints).join("\n")], ["Scan expires", timestamp(scan.expires_at)],
      ]));
      byId("host-key-confirmation").hidden = false;
      hostEditor.status.textContent = "Compare the scanned fingerprints with a trusted independent source. A scan alone does not prove this is the intended host.";
    } catch (cause) { error(hostEditor.error, cause.message); hostEditor.status.textContent = "Scan failed or not confirmed. Nothing was pinned; it was not retried."; }
    finally { hostPending = false; hostEditorControls(); }
  }
  async function pinHostKey() {
    if (!hostDraft || byId("pin-host-key").disabled) return;
    hostPending = true;
    hostEditorControls();
    error(hostEditor.error, "");
    try {
      const result = await api("/api/hosts/pin-key", { host_id: hostDraft.original.id, scan_id: hostScan.scan_id,
        fingerprints: hostScan.fingerprints, expected_revision: hostScan.revision }, 300000);
      showHostPins(result.host);
      hostReviewed = null;
      clearHostScan();
      hostEditor.status.textContent = "Keys pinned. Use Check now on this host to verify the connection against its pinned identity.";
      await loadFleet();
    } catch (cause) {
      clearHostScan();
      error(hostEditor.error, cause.message);
      hostEditor.status.textContent = "Pinning not confirmed. Your draft is kept. Read current hosts and scan again before another explicit confirmation.";
    } finally { hostPending = false; hostEditorControls(); }
  }

  // --- Workload definitions ---
  function showDefinitionEditor() {
    selectTab("workloads");
    editor.panel.hidden = false;
    sideDesk();
    editor.panel.scrollIntoView({ block: "nearest" });
    editor.name.focus({ preventScroll: true });
  }
  function invalidateDefinitionReview() {
    definitionReviewed = null;
    editor.save.disabled = true;
    editor.review.replaceChildren();
    editor.status.textContent = "Draft changed. Review the definition before saving.";
  }
  function definitionControls() {
    const stale = definitionReviewed && fleet?.definition_revision && definitionReviewed.revision !== fleet.definition_revision
      && definitionReviewFleetRevision !== fleet.definition_revision;
    editor.save.disabled = definitionPending || !definitionReviewed || Boolean(stale);
    byId("review-definition").disabled = definitionPending || !definitionDraft;
    byId("cancel-definition").disabled = definitionPending;
    [editor.id, editor.name, editor.purpose, editor.supporting].forEach((field) => { field.disabled = definitionPending || !definitionDraft; });
    if (stale) editor.status.textContent = "The catalog changed. Your draft is kept. Review it again against the current definitions before saving; nothing is overwritten.";
  }
  async function openDefinition(resource, workloadId = null) {
    if (definitionPending) return;
    if (definitionDraft) {
      showDefinitionEditor();
      editor.status.textContent = "Your existing draft is kept. Finish it or close the editor before opening another definition.";
      return;
    }
    definitionPending = true;
    definitionControls();
    error(editor.error, "");
    try {
      const inventory = workloadId ? await api("/api/definitions") : null;
      const original = workloadId ? array(inventory.workloads).find((item) => item.id === workloadId) : null;
      if (workloadId && !original) throw new Error("That definition no longer exists. Refresh to see the current list.");
      definitionDraft = { resourceId: resource?.id, workloadId, original, revision: inventory?.revision };
      definitionReviewed = null;
      editor.form.reset();
      editor.id.value = workloadId || "";
      editor.id.readOnly = Boolean(workloadId);
      editor.name.value = original?.name || text(resource?.name, resource?.native_id);
      editor.purpose.value = original?.purpose || "";
      byId("definition-editor-title").textContent = workloadId ? `Edit ${original.name || workloadId}` : `Define ${text(resource.name, resource.native_id)}`;
      byId("definition-supporting-field").hidden = Boolean(workloadId);
      setOptions(editor.supporting, resource ? fleet.resources.filter((item) => item.id !== resource.id && item.host_id === resource.host_id
        && ["service", "scheduled-job"].includes(item.kind) && !fleet.environments.some((environment) => environment.id === item.id))
        .map((item) => [item.id, `${text(item.name, item.native_id)} / ${text(item.backend)} / ${text(item.scope)}`]) : []);
      Array.from(editor.supporting.options).forEach((option) => { option.selected = false; });
      editor.review.replaceChildren();
      editor.status.textContent = "Describe the service, then review its exact native bindings. Nothing runs on any host.";
      showDefinitionEditor();
    } catch (cause) {
      selectTab("workloads");
      editor.panel.hidden = false;
      sideDesk();
      error(editor.error, cause.message);
    } finally {
      definitionPending = false;
      definitionControls();
      if (definitionDraft) editor.name.focus({ preventScroll: true });
    }
  }
  async function reviewDefinition(event) {
    event.preventDefault();
    if (definitionPending || !definitionDraft) return;
    definitionReviewed = null;
    definitionPending = true;
    definitionControls();
    error(editor.error, "");
    editor.status.textContent = "Reviewing cached data and the current catalog revision.";
    try {
      let proposal;
      if (definitionDraft.workloadId) {
        const inventory = await api("/api/definitions");
        const original = array(inventory.workloads).find((item) => item.id === definitionDraft.workloadId);
        if (!original) throw new Error("That definition no longer exists, so this draft cannot overwrite it.");
        // Refresh untouched canonical fields, preserving only the explicitly edited
        // description. Never replay old bindings over concurrent catalog changes.
        proposal = { definition: { ...original, name: editor.name.value.trim(), purpose: editor.purpose.value.trim() },
          revision: inventory.revision, warnings: [], source_evidence: null };
        definitionDraft.original = original;
      } else {
        proposal = await api("/api/definitions/propose", {
          resource_id: definitionDraft.resourceId, workload_id: editor.id.value.trim(),
          name: editor.name.value.trim(), purpose: editor.purpose.value.trim(),
          supporting_resource_ids: Array.from(editor.supporting.selectedOptions, (option) => option.value),
        });
      }
      if (!proposal.definition || typeof proposal.revision !== "string") throw new Error("Invalid definition review response.");
      definitionReviewed = proposal;
      definitionReviewFleetRevision = fleet?.definition_revision;
      editor.review.replaceChildren(metadata([
        ["Workload", `${proposal.definition.name} (${proposal.definition.id})`], ["Catalog revision", proposal.revision],
        ["Effect", "Definition only. No restart or deployment permission."],
      ]), list(strings(proposal.warnings), "No additional warnings supplied."),
      evidence("definition-reviewed-json", proposal.definition, "Exact definition to save"),
      evidence("definition-source-evidence", proposal.source_evidence, "Source data (cached, JSON)"));
      editor.status.textContent = "Review complete. Saving records metadata only. If the catalog changes first, review again.";
    } catch (cause) { error(editor.error, cause.message); editor.status.textContent = "Review failed. Your draft is kept and nothing was saved."; }
    finally { definitionPending = false; definitionControls(); }
  }
  async function saveDefinition() {
    if (editor.save.disabled || !definitionReviewed || !definitionDraft) return;
    definitionPending = true;
    definitionControls();
    error(editor.error, "");
    editor.status.textContent = "Saving the reviewed definition at its exact catalog revision.";
    try {
      const payload = { definition: definitionReviewed.definition, expected_revision: definitionReviewed.revision };
      if (definitionDraft.workloadId) payload.workload_id = definitionDraft.workloadId;
      const result = await api(`/api/definitions/${definitionDraft.workloadId ? "update" : "save"}`, payload);
      definitionDraft = null;
      definitionReviewed = null;
      editor.review.replaceChildren(metadata([["Saved", result.definition?.name || payload.definition.name], ["Revision", result.revision]]));
      editor.status.textContent = "Definition saved. No restart, deployment or lifecycle permission was granted.";
      await loadFleet();
    } catch (cause) {
      definitionReviewed = null;
      error(editor.error, cause.message);
      editor.status.textContent = "Save not confirmed. Your draft is kept. Review the current definitions before saving again; nothing is overwritten or retried.";
    } finally { definitionPending = false; definitionControls(); }
  }

  // --- Sign-in and access ---
  // The session decides what the page offers; the server enforces it. Passwords and keys never leave their input or the client.
  const SCOPES = ["read", "lease", "operate"];
  const SCOPE_LABELS = { read: "Read", lease: "Lease", operate: "Operate" };
  const SCOPE_MEANING = {
    read: "Sees what this desk shows, without shell scripts, on every host. Changes nothing.",
    lease: "Read, plus take, renew and release device leases on the chosen hosts.",
    operate: "Lease, plus run operations that touch only the chosen hosts.",
  };
  const ACCESS_POLL_MS = 4000;
  const signInUi = {
    panel: byId("sign-in"), form: byId("sign-in-form"), username: byId("sign-in-username"), password: byId("sign-in-password"),
    submit: byId("sign-in-submit"), cancel: byId("sign-in-cancel"), error: byId("sign-in-error"),
  };
  const accessUi = {
    requests: byId("access-requests"), recent: byId("access-recent"), keys: byId("access-keys"), tls: byId("access-tls"),
    status: byId("access-status"), error: byId("access-error"), viewer: byId("access-viewer"), target: byId("access-target"),
    refresh: byId("refresh-access"),
  };
  const isOperator = () => auth?.kind === "operator";
  const canSignIn = () => auth?.kind === "local" && auth.operator_configured !== false;
  const record = (item) => item && typeof item === "object" && !Array.isArray(item);
  const lowerFirst = (value) => value.charAt(0).toLocaleLowerCase() + value.slice(1);
  function accessAvailable() {
    return Boolean(auth) && !signedOut && fleet?.read_only_view !== true && ["operator", "local"].includes(auth.kind);
  }
  function setSession(session) {
    auth = record(session) ? session : null;
    sessionControls();
    if (!canUseCommonsHandoff()) {
      commonsHandoff.panel.hidden = true;
      commonsHandoff.input.value = "";
    }
    renderWorkloads();
  }
  function sessionControls() {
    const shown = Boolean(auth) && !signedOut && fleet?.read_only_view !== true;
    const label = byId("session-label");
    const action = byId("session-action");
    label.hidden = !shown || !isOperator();
    label.textContent = isOperator() ? `Operator: ${text(auth.username, "signed in")}` : "";
    action.hidden = !shown || !(isOperator() || canSignIn());
    action.textContent = isOperator() ? "Sign out" : "Sign in as operator";
    const tab = byId("tab-access");
    tab.hidden = !accessAvailable();
    // While a sign-in screen is up the view stays as it was, so the address keeps its fragment.
    if (tab.hidden && currentTab === "access" && !signedOut && !auth?.login_required) selectTab("workloads");
    if (!accessAvailable()) stopAccessPoll();
    // Operator-only controls on the Playbooks tab follow the session.
    if (pb.list) renderPlaybooks();
    if (lan.data) renderLanUrls();
  }
  function showSignIn(message = "") {
    const blocking = auth?.login_required === true;
    if (blocking) {
      signedOut = true;
      pauseStream();
      stopAccessPoll();
      sessionControls();
    }
    document.documentElement.classList.toggle("is-signed-out", blocking);
    const configured = auth?.operator_configured !== false;
    byId("sign-in-title").textContent = blocking ? "Sign in" : "Sign in as operator";
    byId("sign-in-note").textContent = message || (blocking
      ? (window.location.hash.startsWith("#access/") ? "Sign in to review the access request this link points to." : "This desk is reached over the network, so it shows nothing until the operator signs in.")
      : "Approving lease or operate access, denying requests, revoking keys and other operator-only actions need the operator, even on this machine, because agents here can reach the desk too.");
    byId("sign-in-unset").hidden = configured;
    [signInUi.username, signInUi.password, signInUi.submit].forEach((field) => { field.disabled = !configured; });
    signInUi.cancel.hidden = blocking;
    signInUi.password.value = "";
    error(signInUi.error, "");
    signInUi.panel.hidden = false;
    if (!blocking) window.scrollTo(0, 0);
    (configured ? (signInUi.username.value ? signInUi.password : signInUi.username) : byId("sign-in-title")).focus();
  }
  function hideSignIn() {
    signInUi.panel.hidden = true;
    signInUi.password.value = "";
    error(signInUi.error, "");
  }
  function signInButton(focusKey) {
    const button = node("button", "Sign in as operator", "button quiet");
    button.type = "button";
    button.dataset.focusKey = focusKey;
    button.addEventListener("click", () => { signInReturn = button; showSignIn(); });
    return button;
  }
  function retryMessage(cause) {
    let seconds = Number(cause.retryAfter);
    if (!Number.isFinite(seconds) && typeof cause.retryAfter === "string") seconds = (Date.parse(cause.retryAfter) - Date.now()) / 1000;
    if (cause.retryAfter !== null && Number.isFinite(seconds) && seconds > 0) {
      const minutes = Math.ceil(seconds / 60);
      return `Too many failed sign-ins from this address. Try again after ${clock(Date.now() + seconds * 1000)}, in about ${minutes} ${minutes === 1 ? "minute" : "minutes"}.`;
    }
    return `Too many failed sign-ins. ${cause.message}`;
  }
  function enterDesk() {
    signedOut = false;
    access.located = null;
    document.documentElement.classList.remove("is-signed-out");
    hideSignIn();
    sessionControls();
    fromHash();
    return loadFleet();
  }
  async function signIn(event) {
    event.preventDefault();
    if (signInPending || signInUi.submit.disabled) return;
    signInPending = true;
    signInUi.submit.disabled = true;
    signInUi.submit.textContent = "Signing in…";
    error(signInUi.error, "");
    try {
      const body = { username: signInUi.username.value.trim(), password: signInUi.password.value };
      signInUi.password.value = "";
      const result = await api("/api/auth/login", body);
      let session = null;
      try { session = await api("/api/auth/session"); } catch (cause) { session = null; }
      if (session && session.kind !== "operator") throw new Error("The server accepted the sign-in, but this browser did not send the session back. Open the desk at the exact address the listener uses and try again.");
      setSession(session || { ...auth, authenticated: true, kind: "operator", login_required: false, username: result.username, csrf_token: result.csrf_token });
      if (typeof auth.csrf_token !== "string" && typeof result.csrf_token === "string") auth.csrf_token = result.csrf_token;
      hideSignIn();
      if (signedOut) await enterDesk();
      else {
        access.signature = "";
        renderAccess();
        ui.status.textContent = `Signed in as ${text(auth.username, "the operator")}.`;
        (signInReturn?.isConnected ? signInReturn : byId("session-action")).focus();
      }
    } catch (cause) {
      error(signInUi.error, cause.status === 401 ? "Wrong username or password." : cause.status === 429 ? retryMessage(cause) : cause.message);
      signInUi.password.focus();
    } finally {
      signInPending = false;
      signInUi.submit.disabled = auth?.operator_configured === false;
      signInUi.submit.textContent = "Sign in";
    }
  }
  async function signOut() {
    const button = byId("session-action");
    button.disabled = true;
    error(ui.error, "");
    try { await api("/api/auth/logout", {}); }
    catch (cause) {
      error(ui.error, `Sign-out not confirmed. ${cause.message}`);
      button.disabled = false;
      return;
    }
    let session = null;
    try { session = await api("/api/auth/session"); } catch (cause) { session = null; }
    // Over the network nothing of the desk may stay in memory: start again from the sign-in screen.
    if (!session || session.login_required) { window.location.reload(); return; }
    setSession(session);
    access.signature = "";
    renderAccess();
    ui.status.textContent = "Signed out. Operator-only actions need a new sign-in.";
    button.disabled = false;
    button.focus();
  }
  // Any 401 means the session ended or never existed. Ask the server which, then show the sign-in form.
  function recheckSession() {
    if ((!auth && !sessionUnknown) || sessionCheck || signedOut) return;
    const wasOperator = isOperator();
    sessionCheck = api("/api/auth/session").then((session) => {
      sessionUnknown = false;
      setSession(session);
      if (auth?.login_required) showSignIn("Your session has ended. Sign in again to return to the same view.");
      else if (wasOperator && !isOperator()) {
        ui.status.textContent = "";
        access.signature = "";
        renderAccess();
        showSignIn("Your operator session has ended. Sign in again for operator-only actions.");
      }
    }).catch(() => {}).finally(() => { sessionCheck = null; });
  }

  function stopAccessPoll() {
    window.clearTimeout(access.timer);
    access.timer = null;
  }
  const requestExpired = (item) => Date.parse(item.expires_at) <= Date.now();
  function pendingRequests() { return array(access.enrollments?.pending).filter((item) => record(item) && !requestExpired(item)); }
  // Poll only while someone is looking at the Access tab or a request is waiting, and never in a hidden page.
  function scheduleAccessPoll() {
    stopAccessPoll();
    if (!accessAvailable() || pageClosed || document.hidden) return;
    if (currentTab !== "access" && !pendingRequests().length) return;
    access.timer = window.setTimeout(() => { access.timer = null; loadAccess(); }, ACCESS_POLL_MS);
  }
  async function loadAccess(announce = false) {
    // Cached fleet updates call this too; a hidden page fetches nothing and catches up on `visibilitychange`.
    if (!accessAvailable() || pageClosed || document.hidden) return;
    if (access.loading) { access.again = true; return; }
    stopAccessPoll();
    access.loading = true;
    accessUi.refresh.disabled = true;
    const withKeys = announce || currentTab === "access" || access.keys === null;
    try {
      const [enrollments, keyList] = await Promise.all([api("/api/enrollments"), withKeys ? api("/api/keys") : access.keys]);
      if (!Array.isArray(enrollments.pending) || !Array.isArray(enrollments.recent) || !Array.isArray(keyList)) {
        throw new Error("Access response did not match the enrollment and key contract.");
      }
      access.enrollments = enrollments;
      access.keys = keyList;
      error(accessUi.error, "");
      renderAccess();
      if (announce) accessUi.status.textContent = `Requests and keys read ${clock(Date.now())}.`;
    } catch (cause) {
      error(accessUi.error, cause.message);
      if (announce) accessUi.status.textContent = access.enrollments ? "Reload failed. Showing the last requests and keys received." : "Requests and keys unavailable. Reload to try again.";
    } finally {
      access.loading = false;
      accessUi.refresh.disabled = false;
      if (access.again) { access.again = false; loadAccess(); } else scheduleAccessPoll();
    }
  }
  function allowedScopes(requested) {
    const index = SCOPES.indexOf(requested);
    return SCOPES.slice(0, Math.max(1, index + 1));
  }
  function grantText(scope, hosts) {
    if (scope === "read") return "Read, every host";
    const names = strings(hosts).map(hostName);
    return `${SCOPE_LABELS[scope] || sentence(text(scope))} on ${names.length ? names.join(", ") : "no hosts"}`;
  }
  function requestedText(item) {
    const scope = item.requested_scope;
    if (scope === "read") return "Read";
    const names = strings(item.requested_hosts).map(hostName);
    return `${SCOPE_LABELS[scope] || sentence(text(scope))}${names.length ? ` on ${names.join(", ")}` : ", without naming hosts: choose them when approving"}`;
  }
  function countdown(expiresAt) {
    const element = node("span", "", "countdown");
    element.dataset.expiresAt = text(expiresAt, "");
    updateCountdown(element);
    return element;
  }
  function updateCountdown(element) {
    const left = (Date.parse(element.dataset.expiresAt) - Date.now()) / 1000;
    element.title = timestamp(element.dataset.expiresAt);
    if (!Number.isFinite(left)) { element.textContent = "Unknown"; return; }
    element.textContent = left <= 0 ? "Expired. The client has to ask again." : left < 60 ? "Less than a minute" : `${Math.ceil(left / 60)} min`;
    element.classList.toggle("caution", left < 120);
    const card = element.closest(".request-card");
    if (card && left <= 0 && !card.classList.contains("is-expired")) {
      card.classList.add("is-expired");
      card.querySelectorAll("[data-live]").forEach((button) => { button.disabled = true; });
      updateAccessBadge();
    }
  }
  function updateAccessBadge() {
    const count = pendingRequests().length;
    const badge = byId("access-badge");
    badge.textContent = count ? String(count) : "";
    badge.hidden = !count;
    byId("tab-access").title = count ? `${count} access ${count === 1 ? "request" : "requests"} waiting` : "";
    byId("requests-count").textContent = access.enrollments ? `${count} waiting` : "";
  }
  function focusKey(root, key) {
    Array.from(root.querySelectorAll("[data-focus-key]")).find((item) => item.dataset.focusKey === key)?.focus();
  }
  function confirmBox(key, question, confirmLabel, keepLabel, onConfirm) {
    const yes = node("button", access.busy === key ? "Working…" : confirmLabel, "button primary");
    yes.type = "button";
    yes.dataset.focusKey = `confirm:${key}`;
    yes.dataset.live = "true";
    yes.disabled = access.busy !== null;
    yes.addEventListener("click", onConfirm);
    const keep = node("button", keepLabel, "button quiet");
    keep.type = "button";
    keep.disabled = access.busy !== null;
    keep.addEventListener("click", () => {
      access.confirm = null;
      renderAccess(true);
      focusKey(byId("panel-access"), `open:${key}`);
    });
    return group("div", "approval confirm-box", node("p", question), group("div", "body-actions", yes, keep));
  }

  function approveDraft(item) {
    if (!access.drafts.has(item.id)) {
      const allowed = allowedScopes(item.requested_scope);
      const registry = new Set(array(fleet?.hosts).map((host) => host.id));
      access.drafts.set(item.id, { scope: allowed[allowed.length - 1], hosts: new Set(strings(item.requested_hosts).filter((id) => registry.has(id))), days: "90", label: "" });
    }
    return access.drafts.get(item.id);
  }
  function approveForm(item) {
    const id = item.id;
    const draft = approveDraft(item);
    const form = node("form", undefined, "operation-form request-approve");
    form.noValidate = true;
    form.setAttribute("aria-label", `Approve the request from ${text(item.name, "this client")}`);
    const scope = node("select");
    allowedScopes(item.requested_scope).forEach((value) => {
      const option = node("option", `${SCOPE_LABELS[value]}${value === item.requested_scope ? " (requested)" : ""}`);
      option.value = value;
      scope.append(option);
    });
    scope.value = draft.scope;
    scope.dataset.focusKey = `approve:${id}:scope`;
    const scopeNote = node("span", "", "field-note");
    const scopeLabel = node("label", "Scope");
    scopeLabel.append(scope, scopeNote);
    const days = node("input");
    Object.assign(days, { type: "number", min: "1", max: "365", step: "1", required: true, value: draft.days, inputMode: "numeric" });
    days.dataset.focusKey = `approve:${id}:days`;
    const daysLabel = node("label", "Expires after, days");
    daysLabel.append(days, node("span", "1 to 365.", "field-note"));
    const label = node("input");
    Object.assign(label, { maxLength: 128, autocomplete: "off", placeholder: text(item.name, ""), value: draft.label });
    label.dataset.focusKey = `approve:${id}:label`;
    const labelLabel = node("label", "Label");
    labelLabel.append(label, node("span", "Optional. Names the key in the list below.", "field-note"));

    const hostSet = node("fieldset", undefined, "host-choices");
    hostSet.append(node("legend", "Hosts"), node("p", "Required for lease and operate. The key can lease devices and run operations on these hosts only.", "field-note"));
    const registry = array(fleet?.hosts);
    const missing = strings(item.requested_hosts).filter((hostId) => !registry.some((host) => host.id === hostId));
    if (missing.length) hostSet.append(node("p", `Requested but not in the host registry, so they cannot be granted: ${missing.join(", ")}.`, "row-attention"));
    if (!registry.length) hostSet.append(empty("The host list has not loaded yet."));
    else {
      const choices = node("ul", undefined, "host-choice-list");
      registry.forEach((host) => {
        const box = node("input");
        box.type = "checkbox";
        box.value = host.id;
        box.checked = draft.hosts.has(host.id);
        box.dataset.focusKey = `approve:${id}:host:${host.id}`;
        box.addEventListener("change", () => {
          if (box.checked) draft.hosts.add(host.id); else draft.hosts.delete(host.id);
          check();
        });
        const name = hostLabel(host);
        const choice = group("label", "check-label", box, node("span", name));
        if (name !== host.id) choice.append(node("span", host.id, "machine row-sub"));
        choices.append(group("li", "", choice));
      });
      hostSet.append(choices);
    }
    const problem = node("p", "", "row-attention");
    const submit = node("button", access.busy === `approve:${id}` ? "Approving…" : "Approve", "button primary");
    submit.type = "submit";
    submit.dataset.live = "true";
    submit.dataset.focusKey = `approve:${id}:submit`;
    const cancel = node("button", "Cancel", "button quiet");
    cancel.type = "button";
    cancel.disabled = access.busy !== null;
    cancel.addEventListener("click", () => {
      access.drafts.delete(id);
      renderAccess(true);
      focusKey(accessUi.requests, `open:approve:${id}`);
    });
    function check() {
      const daysValue = Number(draft.days);
      const operatorNeeded = draft.scope !== "read" && !isOperator();
      problem.replaceChildren();
      if (operatorNeeded) problem.append(`${SCOPE_LABELS[draft.scope]} access needs the operator. Choose Read to approve it as read-only${canSignIn() ? ", or" : "."}`, canSignIn() ? " " : "", canSignIn() ? signInButton(`approve:${id}:sign-in`) : "");
      else if (draft.scope !== "read" && !draft.hosts.size) problem.append("Choose at least one host.");
      else if (!Number.isInteger(daysValue) || daysValue < 1 || daysValue > 365) problem.append("Expiry must be a whole number of days from 1 to 365.");
      problem.hidden = !problem.childNodes.length;
      hostSet.hidden = draft.scope === "read";
      scopeNote.textContent = SCOPE_MEANING[draft.scope] || "";
      submit.disabled = !problem.hidden || access.busy !== null || requestExpired(item);
    }
    scope.addEventListener("change", () => { draft.scope = scope.value; check(); });
    days.addEventListener("input", () => { draft.days = days.value; check(); });
    label.addEventListener("input", () => { draft.label = label.value; });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      check();
      if (!submit.disabled) approveRequest(item, draft);
    });
    form.append(group("div", "operation-fields", scopeLabel, daysLabel, labelLabel), hostSet, problem, group("div", "shell-actions", submit, cancel));
    check();
    return form;
  }
  function requestCard(item) {
    const id = text(item.id, "");
    const card = node("article", undefined, "request-card");
    card.id = `request-${id}`;
    card.tabIndex = -1;
    card.dataset.focusKey = `request:${id}`;
    card.classList.toggle("is-target", access.target === id);
    card.classList.toggle("is-expired", requestExpired(item));
    const scope = item.requested_scope;
    card.append(group("div", "request-head",
      group("p", "request-code-block", node("span", "Code", "request-code-label"), node("strong", text(item.code), "request-code")),
      node("p", "Check that this code matches the one the client printed. If it does not, deny the request.", "request-check")));
    card.append(metadata([
      ["Name", text(item.name, "Not given")], ["User", text(item.user, "Not given")],
      ["Host", item.host_id ? hostName(item.host_id) : "Not given"], ["Agent", text(item.agent_id, "Not given")],
      ["From address", text(item.source_address)], ["Asks for", requestedText(item)],
      ["Asked", timestamp(item.created_at)], ["Time left", countdown(item.expires_at)],
    ]));
    if (scope !== "read" && !isOperator() && !access.drafts.has(id)) {
      card.append(group("p", "row-attention", `${SCOPE_LABELS[scope] || sentence(text(scope))} access needs the operator. You can approve it as read-only.`,
        canSignIn() ? " " : "", canSignIn() ? signInButton(`request:${id}:sign-in`) : ""));
    }
    if (access.drafts.has(id)) card.append(approveForm(item));
    else if (access.confirm === `deny:${id}`) {
      card.append(confirmBox(`deny:${id}`, `Deny the request from ${text(item.name, "this client")}? It is told it was denied and gets no access.`, "Deny request", "Keep it waiting", () => denyRequest(item)));
    } else {
      const approve = node("button", "Approve…", "button secondary");
      approve.type = "button";
      approve.dataset.focusKey = `open:approve:${id}`;
      approve.dataset.live = "true";
      approve.disabled = access.busy !== null || requestExpired(item);
      approve.addEventListener("click", () => {
        approveDraft(item);
        access.confirm = null;
        renderAccess(true);
        focusKey(accessUi.requests, `approve:${id}:scope`);
      });
      const actions = group("div", "body-actions", approve);
      if (isOperator()) {
        const deny = node("button", "Deny…", "button quiet");
        deny.type = "button";
        deny.dataset.focusKey = `open:deny:${id}`;
        deny.dataset.live = "true";
        deny.disabled = access.busy !== null || requestExpired(item);
        deny.addEventListener("click", () => {
          access.confirm = `deny:${id}`;
          renderAccess(true);
          focusKey(accessUi.requests, `confirm:deny:${id}`);
        });
        actions.append(deny);
      }
      card.append(actions);
    }
    return card;
  }
  async function approveRequest(item, draft) {
    if (access.busy) return;
    const payload = { scope: draft.scope, expires_in_days: Number(draft.days) };
    if (draft.scope !== "read") payload.hosts = array(fleet?.hosts).map((host) => host.id).filter((hostId) => draft.hosts.has(hostId));
    if (draft.label.trim()) payload.label = draft.label.trim();
    access.busy = `approve:${item.id}`;
    error(accessUi.error, "");
    accessUi.status.textContent = `Approving the request from ${text(item.name, "the client")}.`;
    renderAccess(true);
    let approved = false;
    try {
      const key = await api(`/api/enrollments/${encodeURIComponent(item.id)}/approve`, payload);
      approved = true;
      access.drafts.delete(item.id);
      accessUi.status.textContent = `Approved ${text(item.name, "the request")}: key ${text(key.label, text(key.id, ""))}, ${lowerFirst(grantText(key.scope, key.hosts))}, expires ${timestamp(key.expires_at)}. The client sees the approval on its next check.`;
    } catch (cause) {
      error(accessUi.error, cause.message);
      accessUi.status.textContent = "Approval not confirmed. Your choices are kept.";
    } finally {
      access.busy = null;
      renderAccess(true);
      await loadAccess();
      if (approved) byId("requests-title").focus();
      else focusKey(accessUi.requests, `approve:${item.id}:submit`);
    }
  }
  async function denyRequest(item) {
    if (access.busy) return;
    access.busy = `deny:${item.id}`;
    error(accessUi.error, "");
    renderAccess(true);
    let denied = false;
    try {
      await api(`/api/enrollments/${encodeURIComponent(item.id)}/deny`, {});
      denied = true;
      access.confirm = null;
      accessUi.status.textContent = `Denied the request from ${text(item.name, "the client")}. It gets no access.`;
    } catch (cause) {
      error(accessUi.error, cause.message);
      accessUi.status.textContent = "Denial not confirmed.";
    } finally {
      access.busy = null;
      renderAccess(true);
      await loadAccess();
      if (denied) byId("requests-title").focus();
    }
  }
  function renderRequests() {
    const pending = array(access.enrollments?.pending).filter(record);
    if (!access.enrollments) accessUi.requests.replaceChildren(empty("Loading requests."));
    else if (!pending.length) accessUi.requests.replaceChildren(empty("No requests waiting. On a new host, switchyard enroll --server https://… asks for access and prints a link to this tab."));
    else accessUi.requests.replaceChildren(...pending.map(requestCard));
    // Drafts for requests that are gone (approved elsewhere, denied, cleared) are dropped.
    const ids = new Set(pending.map((item) => item.id));
    Array.from(access.drafts.keys()).filter((id) => !ids.has(id)).forEach((id) => access.drafts.delete(id));
  }
  function decisionText(item) {
    const status = text(item.status, "unknown");
    if (status === "expired") return `Expired${item.expires_at ? ` ${ageLabel(ageSeconds(item.expires_at))}` : ""} without a decision`;
    return `${sentence(status)}${item.decided_by ? ` by ${item.decided_by}` : ""}${item.decided_at ? ` ${ageLabel(ageSeconds(item.decided_at))}` : ""}`;
  }
  function renderRecent() {
    const recent = array(access.enrollments?.recent).filter(record);
    if (!recent.length) { accessUi.recent.replaceChildren(); return; }
    const rows = recent.map((item) => {
      const row = group("li", "recent-row", node("strong", text(item.code), "machine"),
        node("span", `${text(item.name, "Unnamed")}${item.user ? `, ${item.user}` : ""}${item.host_id ? ` on ${hostName(item.host_id)}` : ""}`),
        node("span", `asked for ${lowerFirst(requestedText(item))}`, "row-sub"),
        node("span", decisionText(item), "recent-decision"));
      row.id = `request-${text(item.id, "")}`;
      row.tabIndex = -1;
      row.classList.toggle("is-target", access.target === item.id);
      return row;
    });
    accessUi.recent.replaceChildren(disclosure("access-recent", `Recent decisions (${recent.length})`, group("ul", "recent-list", ...rows), "record access-recent"));
  }
  function accessKeyState(key) {
    if (key.revoked_at) return "revoked";
    return Date.parse(key.expires_at) <= Date.now() ? "expired" : "active";
  }
  async function revokeKey(key) {
    if (access.busy) return;
    const name = text(key.label, text(key.name, key.id));
    access.busy = `revoke:${key.id}`;
    error(accessUi.error, "");
    renderAccess(true);
    let revoked = false;
    try {
      await api(`/api/keys/${encodeURIComponent(key.id)}/revoke`, {});
      revoked = true;
      access.confirm = null;
      accessUi.status.textContent = `Revoked ${name}. Requests with it are refused from now on.`;
    } catch (cause) {
      error(accessUi.error, cause.message);
      accessUi.status.textContent = `Revoking ${name} is not confirmed. Reload to see its state.`;
    } finally {
      access.busy = null;
      renderAccess(true);
      await loadAccess();
      if (revoked) byId("keys-title").focus();
    }
  }
  function accessKeyRow(key) {
    const state = accessKeyState(key);
    const id = text(key.id, "");
    const row = node("div", undefined, `key-row is-${state}`);
    row.id = `key-${id}`;
    const who = [text(key.name, ""), key.user && `user ${key.user}`, key.host_id && `host ${hostName(key.host_id)}`, key.agent_id && `agent ${key.agent_id}`].filter(Boolean).join(", ");
    const stateText = state === "revoked" ? `Revoked ${timestamp(key.revoked_at)}` : state === "expired" ? `Expired ${timestamp(key.expires_at)}` : "Active";
    const used = node("span", key.last_used_at ? `Last used ${ageLabel(ageSeconds(key.last_used_at))}` : "Never used", "key-used");
    used.title = key.last_used_at ? timestamp(key.last_used_at) : "";
    row.append(
      group("span", "key-identity", node("strong", text(key.label, text(key.name, id))), node("span", who || "No identity recorded", "row-sub"), node("span", id, "machine row-sub")),
      group("span", "key-grant", node("span", grantText(key.scope, key.hosts)), node("span", SCOPE_MEANING[key.scope] || "", "row-sub")),
      group("span", "key-state", group("span", "cell-state", lamp({ active: "run", expired: "done", revoked: "halt" }[state], stateText), node("span", stateText)),
        node("span", `Created ${timestamp(key.created_at)}`, "row-sub"), state === "active" && node("span", `Expires ${timestamp(key.expires_at)}`, "row-sub")),
      group("span", "key-last", used, key.last_used_from && node("span", `from ${key.last_used_from}`, "machine row-sub")));
    if (isOperator() && state === "active") {
      if (access.confirm === `revoke:${id}`) {
        row.append(confirmBox(`revoke:${id}`, `Revoke ${text(key.label, text(key.name, id))}? Every request with this key is refused from then on. This cannot be undone; the client has to ask again.`, "Revoke key", "Keep it", () => revokeKey(key)));
      } else {
        const revoke = node("button", "Revoke…", "button secondary");
        revoke.type = "button";
        revoke.dataset.focusKey = `open:revoke:${id}`;
        revoke.disabled = access.busy !== null;
        revoke.addEventListener("click", () => {
          access.confirm = `revoke:${id}`;
          renderAccess(true);
          focusKey(accessUi.keys, `confirm:revoke:${id}`);
        });
        row.append(group("span", "key-actions", revoke));
      }
    }
    return row;
  }
  function renderKeys() {
    const all = array(access.keys).filter(record);
    const active = all.filter((key) => accessKeyState(key) === "active");
    const inactive = all.filter((key) => accessKeyState(key) !== "active");
    byId("keys-count").textContent = access.keys ? `${active.length} active${inactive.length ? `, ${inactive.length} expired or revoked` : ""}` : "";
    byId("keys-note").textContent = `Each key works until it expires or is revoked. A revoked key is refused at once.${isOperator() ? "" : " Revoking a key needs the operator."}`;
    if (!access.keys) { accessUi.keys.replaceChildren(empty("Loading keys.")); return; }
    const rows = active.map(accessKeyRow);
    if (inactive.length) rows.push(disclosure("keys-inactive", `${inactive.length} expired or revoked`, group("div", "key-list-inactive", ...inactive.map(accessKeyRow)), "record key-inactive"));
    accessUi.keys.replaceChildren(...(rows.length ? rows : [empty("No keys yet. Approving a request creates one.")]));
  }
  function fingerprint(value) {
    const hex = text(value, "").replace(/^sha256:/i, "").replaceAll(":", "").toLowerCase();
    return /^[0-9a-f]{64}$/.test(hex) ? hex.toUpperCase().match(/../g).join(":") : text(value, "");
  }
  function renderTls() {
    const tls = record(auth?.tls) ? auth.tls : {};
    const print = fingerprint(tls.ca_fingerprint_sha256);
    const link = node("a", "Download the CA certificate");
    link.href = "/api/tls/ca";
    link.download = "switchyard-ca.pem";
    accessUi.tls.replaceChildren(node("p", tls.enabled === true
      ? "This page reached the desk over HTTPS, with a certificate from Switchyard's own certificate authority (CA)."
      : "This page is served over plain HTTP on the desk itself. The network listener uses HTTPS, with a certificate from Switchyard's own certificate authority (CA).", "section-note"),
    metadata([["CA fingerprint, SHA-256", print ? node("span", print, "machine fingerprint") : "Not reported by the server"]]),
    group("p", "section-note", link, ". Install it as a trusted authority on each phone or computer you use to reach this desk over the network, after checking that its fingerprint matches what ",
      node("code", "switchyard tls show"), " prints on the control host."));
  }
  function renderAccessTarget() {
    const target = access.target;
    const box = accessUi.target;
    if (!target || !access.enrollments) { box.hidden = true; box.textContent = ""; return; }
    const pending = array(access.enrollments.pending).find((item) => record(item) && item.id === target);
    const recent = array(access.enrollments.recent).find((item) => record(item) && item.id === target);
    let message = "";
    if (pending && requestExpired(pending)) message = "The request from the link has expired. The client has to ask again.";
    else if (!pending && recent?.status === "expired") message = "The request from the link has expired. The client has to ask again.";
    else if (!pending && recent) message = `The request from the link (code ${text(recent.code)}) was ${lowerFirst(decisionText(recent))}.`;
    else if (!pending) message = "No request matches the link. It may have expired and been cleared, or the link is incomplete. The client has to ask again.";
    box.textContent = message;
    box.hidden = !message;
    // Wait for the host list: the first full render after it replaces these rows and would drop the focus.
    if (access.located === target || !fleet) return;
    access.located = target;
    const element = byId(`request-${target}`);
    if (!element) return;
    element.closest("details")?.setAttribute("open", "");
    // Jump first: cached updates arriving during a smooth scroll restore the old position and would cancel it.
    element.scrollIntoView({ block: "center" });
    locate(element);
  }
  function renderViewerNote() {
    const box = accessUi.viewer;
    if (isOperator()) { box.hidden = true; box.replaceChildren(); return; }
    box.hidden = false;
    box.replaceChildren("You are on the desk itself without an operator sign-in. You can approve requests as read-only; lease and operate access, denying requests and revoking keys need the operator.",
      auth?.operator_configured === false ? " No operator password is set: set one on the control host with switchyard auth set-password." : "",
      canSignIn() ? " " : "", canSignIn() ? signInButton("viewer:sign-in") : "");
  }
  // Polls rebuild the lists only when something changed. Open forms keep their choices in `access.drafts`.
  function renderAccess(force = false) {
    if (!auth) return;
    const signature = JSON.stringify([access.enrollments, access.keys, auth.kind, auth.operator_configured, auth.tls, array(fleet?.hosts).map((host) => [host.id, host.name]), access.target]);
    updateAccessBadge();
    if (!force && signature === access.signature) return;
    access.signature = signature;
    renderViewerNote();
    rerender(accessUi.requests, renderRequests);
    rerender(accessUi.recent, renderRecent);
    rerender(accessUi.keys, renderKeys);
    renderTls();
    renderAccessTarget();
  }
  async function boot() {
    let session = null;
    let failure = "";
    try { session = await api("/api/auth/session"); }
    catch (cause) {
      // 404: a server without sign-in, so the page behaves as before. Anything else is unknown; a later 401 asks again.
      if (cause.status !== 404) { sessionUnknown = true; failure = `Sign-in state unknown: ${cause.message}`; }
    }
    setSession(session);
    if (auth?.login_required) { showSignIn(); return; }
    await enterDesk();
    if (failure && !ui.error.textContent) error(ui.error, failure);
  }

  // --- Playbooks (Ansible) ---
  // Reading contacts no host. Registering, planning and applying need the operator's session; the server enforces it.
  // A sudo password typed here goes into one request for one run. It is never kept in page state, storage or the address.
  const RUN_POLL_MS = 1500;
  const RUN_ACTIVE = new Set(["queued", "running"]);
  const RUN_ASPECTS = { queued: "transit", running: "transit", planned: "run", succeeded: "run", failed: "fail", busy: "halt",
    interrupted: "halt", "needs-inspection": "transit", "needs-operator-privilege": "idle" };
  const RUN_WORDS = { queued: "Waiting", running: "Running", planned: "Planned", succeeded: "Applied", failed: "Failed",
    busy: "Host busy", interrupted: "Interrupted", "needs-inspection": "Needs inspection", "needs-operator-privilege": "Needs the sudo password" };
  const CHECK_TRUST = {
    full: "Full: a plan predicts every change.",
    partial: "Partial: a plan predicts some changes; the rest are listed as not predicted.",
    unsupported: "Unsupported: a plan checks access only and predicts nothing.",
  };
  const TASK_ASPECTS = { ok: "run", changed: "transit", failed: "fail", unreachable: "fail", skipped: "dark" };
  const pb = { list: null, configured: true, note: "", details: new Map(), loading: new Set(), runs: null, timer: null,
    editor: null, runner: null, confirm: null, busy: false, pendingRun: null };
  const pbUi = {
    list: byId("playbook-list"), runs: byId("ansible-runs"), status: byId("playbooks-status"), error: byId("playbooks-error"),
    viewer: byId("playbooks-viewer"), editor: byId("playbook-editor"), run: byId("run-panel"), add: byId("add-playbook"),
    refresh: byId("refresh-playbooks"),
  };
  const shortCommit = (value) => typeof value === "string" ? value.slice(0, 10) : "unknown";
  const valueText = (value) => value === null || value === undefined ? "no value" : typeof value === "string" ? value : JSON.stringify(value);
  const runWord = (status) => RUN_WORDS[status] || sentence(text(status));
  const playbookById = (id) => array(pb.list).find((item) => item.id === id);
  const activeRuns = () => array(pb.runs).filter((run) => RUN_ACTIVE.has(run.status));
  function button(label, className, focusKey, onClick) {
    const element = node("button", label, `button ${className}`);
    element.type = "button";
    if (focusKey) element.dataset.focusKey = focusKey;
    if (onClick) element.addEventListener("click", onClick);
    return element;
  }
  function field(labelText, control, note) {
    const label = node("label", labelText);
    label.append(control);
    if (note) label.append(node("span", note, "field-note"));
    return label;
  }
  function sudoState(item, hostId) {
    const host = array(item?.hosts).find((entry) => entry.host_id === hostId);
    return host?.passwordless_sudo === true ? "passwordless" : host?.passwordless_sudo === false ? "password" : "unknown";
  }

  async function loadPlaybooks(announce = false) {
    if (signedOut || pageClosed) return;
    pbUi.refresh.disabled = true;
    try {
      const [view, runs] = await Promise.all([api("/api/ansible/playbooks"), api("/api/ansible/runs")]);
      pb.configured = view.configured !== false;
      pb.note = pb.configured ? "" : text(view.error, "Ansible is not configured on this desk.");
      pb.list = array(view.playbooks).filter(record);
      pb.runs = array(runs.runs).filter(record);
      error(pbUi.error, "");
      if (announce) pbUi.status.textContent = `Playbooks and runs read ${clock(Date.now())}.`;
    } catch (cause) {
      error(pbUi.error, cause.message);
    } finally { pbUi.refresh.disabled = false; }
    renderPlaybooks();
    renderRuns();
    if (pb.pendingRun) {
      const id = pb.pendingRun;
      pb.pendingRun = null;
      openRun(id);
    }
    schedulePlaybookPoll();
  }
  async function loadDetail(id, force = false) {
    if ((!force && pb.details.has(id)) || pb.loading.has(id)) return pb.details.get(id);
    pb.loading.add(id);
    try {
      pb.details.set(id, await api(`/api/ansible/playbooks/${encodeURIComponent(id)}`, undefined, 330000));
    } catch (cause) {
      pb.details.set(id, { error: cause.message });
    } finally { pb.loading.delete(id); }
    renderPlaybooks();
    return pb.details.get(id);
  }
  // Poll only while a run is active and someone can see it: on this tab, or in an open run panel. Never in a hidden page.
  function schedulePlaybookPoll() {
    window.clearTimeout(pb.timer);
    pb.timer = null;
    const watching = Boolean(pb.runner?.runId) && RUN_ACTIVE.has(pb.runner.run?.status);
    if (pageClosed || document.hidden || signedOut || (!activeRuns().length && !watching)) return;
    if (currentTab !== "playbooks" && !watching) return;
    pb.timer = window.setTimeout(() => { pb.timer = null; pollRuns(); }, RUN_POLL_MS);
  }
  async function pollRuns() {
    try {
      const before = new Map(array(pb.runs).map((run) => [run.id, run.status]));
      pb.runs = array((await api("/api/ansible/runs")).runs).filter(record);
      renderRuns();
      const ended = pb.runs.filter((run) => RUN_ACTIVE.has(before.get(run.id)) && !RUN_ACTIVE.has(run.status));
      if (pb.runner?.runId) await refreshRunner();
      if (ended.length) {
        // An ended run changes plans, receipts, sudo state and the Audit log: read them again once.
        new Set(ended.map((run) => run.playbook_id)).forEach((id) => { if (pb.details.has(id)) loadDetail(id, true); });
        const view = await api("/api/ansible/playbooks");
        pb.list = array(view.playbooks).filter(record);
        renderPlaybooks();
        if (ended.some((run) => run.kind === "apply")) refreshReceipts();
      }
    } catch (cause) { error(pbUi.error, cause.message); }
    schedulePlaybookPoll();
  }

  function renderPlaybooks() {
    const operator = isOperator();
    pbUi.add.hidden = !operator || !pb.configured;
    const showViewer = !operator && fleet?.read_only_view !== true && Boolean(auth);
    pbUi.viewer.hidden = !showViewer;
    pbUi.viewer.replaceChildren(...(showViewer ? ["Adding playbooks, planning and applying need the operator, even on this machine: a playbook with sudo is root on its host.",
      canSignIn() ? " " : "", canSignIn() ? signInButton("playbooks:sign-in") : ""] : []));
    const list = array(pb.list);
    byId("playbook-count").textContent = pb.list ? `${list.length} registered` : "";
    rerender(pbUi.list, () => {
      if (!pb.configured) pbUi.list.replaceChildren(empty(pb.note));
      else if (!pb.list) pbUi.list.replaceChildren(empty("Loading playbooks."));
      else if (!list.length) pbUi.list.replaceChildren(empty(operator ? "No playbooks registered. Add playbook… reads a repository in your home directory." : "No playbooks registered."));
      else pbUi.list.replaceChildren(...list.map(playbookRow));
    });
  }
  function playbookRow(item) {
    const repo = record(item.repo_state) ? item.repo_state : {};
    const hosts = array(item.hosts).filter(record);
    const summary = group("span", "record-summary",
      node("span", text(item.id), "record-name machine"),
      repo.error ? node("span", "Repository unreadable", "row-attention")
        : node("span", `${shortCommit(repo.commit)}${repo.dirty ? ", uncommitted changes" : ""}`, repo.dirty ? "caution machine" : "record-state machine"),
      node("span", hosts.map((host) => hostName(host.host_id)).join(", ") || "No hosts", "record-state"),
      item.become === true ? node("span", "Needs sudo", "badge") : null);
    const body = node("div", undefined, "record-body");
    const details = disclosure(`playbook:${item.id}`, summary, body, "record playbook-row");
    details.id = `playbook-${item.id}`;
    body.append(...playbookBody(item));
    details.addEventListener("toggle", () => { if (details.open) loadDetail(item.id); });
    if (details.open && !pb.details.has(item.id)) loadDetail(item.id);
    return details;
  }
  function hostsCell(item) {
    const hosts = array(item.hosts).filter(record);
    if (!hosts.length) return "No hosts";
    return group("ul", "text-list compact", ...hosts.map((host) => {
      const sudo = host.passwordless_sudo === true ? "passwordless sudo" : host.passwordless_sudo === false ? "sudo needs a password" : "sudo not checked yet";
      return group("li", "", node("span", hostName(host.host_id)), node("span", host.eligible ? ` · ${sudo}` : ` · cannot run: ${text(host.reason)}`, host.eligible ? "row-sub inline" : "row-attention inline"));
    }));
  }
  function playbookBody(item) {
    const detail = pb.details.get(item.id);
    const repo = record(item.repo_state) ? item.repo_state : {};
    const parts = [node("p", text(item.description, ""), "section-note"), metadata([
      ["Repository", node("span", text(item.repo), "machine")],
      ["Commit", repo.error ? node("span", repo.error, "row-attention") : node("span", `${text(repo.commit)}${repo.dirty
        ? ` (working tree has ${repo.changed_paths} uncommitted ${repo.changed_paths === 1 ? "change" : "changes"})` : " (clean working tree)"}`, "machine")],
      ["Playbook file", node("span", text(item.playbook), "machine")],
      ["Inventory", item.inventory ? node("span", item.inventory, "machine") : "None: hosts get only Switchyard's connection settings"],
      ["Groups the host joins", strings(item.groups).join(", ")],
      ["May run on", hostsCell(item)],
      ["Privilege", item.become ? "Uses sudo (become) on the host" : "Runs without sudo"],
      ["Check mode", CHECK_TRUST[item.check_mode] || text(item.check_mode)],
      ["Registration", `Revision ${item.revision}, ${timestamp(item.registered?.updated_at)}, by ${text(item.registered?.updated_by)}`],
    ])];
    if (isOperator()) {
      if (pb.confirm === `remove:${item.id}`) {
        parts.push(group("div", "approval confirm-box", node("p", `Remove the registration of ${item.id}? Its plans and receipts stay; nothing on any host changes.`),
          group("div", "body-actions",
            button(pb.busy ? "Removing…" : "Remove registration", "primary", `confirm:remove:${item.id}`, () => removePlaybook(item)),
            button("Keep it", "quiet", null, () => { pb.confirm = null; renderPlaybooks(); focusKey(pbUi.list, `remove:${item.id}`); }))));
      } else {
        parts.push(group("div", "body-actions",
          button("Plan a run…", "secondary", `run:${item.id}`, () => openRunner(item.id)),
          button("Edit…", "quiet", `edit:${item.id}`, () => openEditor("edit", item.id)),
          button("Remove…", "quiet", `remove:${item.id}`, () => { pb.confirm = `remove:${item.id}`; renderPlaybooks(); focusKey(pbUi.list, `confirm:remove:${item.id}`); })));
      }
    }
    if (!detail) parts.push(empty(pb.loading.has(item.id) ? "Reading the repository…" : "Open this entry to read the repository."));
    else if (detail.error) parts.push(node("p", detail.error, "row-attention"));
    else {
      if (detail.discovery?.error) parts.push(node("p", `Variables unavailable: ${detail.discovery.error}`, "row-attention"));
      else parts.push(...discoveryView(detail.discovery));
      parts.push(...historyView(detail));
    }
    return parts;
  }
  function typeLabel(v) {
    const choices = Array.isArray(v.choices) ? ` (one of ${v.choices.map(valueText).join(", ")})` : "";
    return `${v.type === "list" && v.elements ? `list of ${v.elements}` : text(v.type, "text")}${choices}`;
  }
  function discoveryView(d) {
    const variables = array(d.variables).filter(record);
    const parts = [node("h4", "Variables")];
    if (!variables.length) parts.push(empty("The playbook exposes no variables Switchyard can see."));
    else {
      const rows = variables.map((v) => [
        group("span", "var-name", node("span", v.name, "machine"), v.secret ? node("span", "secret", "badge") : null,
          v.required ? node("span", "required", "badge") : null),
        typeLabel(v),
        v.secret ? "Not shown" : v.default ? `${valueText(v.default.value)} (${v.default.source})` : "None",
        v.overridable ? "Yes" : "No",
        text(v.description, ""),
      ]);
      parts.push(group("div", "table-scroll", table(["Variable", "Type", "Playbook value", "May override", "Description"], rows,
        "Templates are shown as written. Switchyard never evaluates them.")));
    }
    Object.entries(record(d.hosts) ? d.hosts : {}).forEach(([hostId, host]) => {
      const rows = variables.filter((v) => v.effective?.[hostId]).map((v) => {
        const entry = v.effective[hostId];
        return [node("span", v.name, "machine"), entry.hidden ? "Not shown (secret)" : valueText(entry.value), `${entry.source}, ${entry.origin}`];
      });
      const known = new Set(variables.map((v) => v.name));
      Object.entries(record(host.values) ? host.values : {}).filter(([name]) => !known.has(name)).forEach(([name, entry]) => {
        rows.push([node("span", name, "machine"), entry.hidden ? "Not shown (secret)" : valueText(entry.value), `repository inventory, ${entry.origin}`]);
      });
      const content = host.error ? node("p", host.error, "row-attention") : rows.length
        ? group("div", "table-scroll", table(["Variable", "Starting value", "From"], rows)) : empty("Nothing set for this host.");
      parts.push(disclosure(`starting:${d.playbook_id}:${hostId}`, `What ${hostName(hostId)} starts with`, content, "record nested"));
    });
    const plays = array(d.plays).filter(record).map((play) => play.import_playbook ? `Imports ${play.import_playbook}`
      : `${text(play.name, "Unnamed play")}: hosts ${text(play.hosts, "?")}${play.become ? ", with sudo" : ""}${strings(play.roles).length ? `; roles ${strings(play.roles).join(", ")}` : ""}`);
    parts.push(node("h4", "Plays and roles"), list(plays, "No plays found."),
      list(array(d.roles).filter(record).map((role) => `${role.name}: ${role.path || role.note}`), "No roles."));
    const problems = [...strings(d.problems), ...array(d.skipped).filter(record).map((item) => `${item.path}: ${item.reason}`)];
    if (problems.length) parts.push(node("h4", "Not read"), list(problems, ""));
    return parts;
  }
  function historyView(detail) {
    const parts = [node("h4", "Recent runs")];
    const runs = array(detail.runs).filter(record);
    parts.push(runs.length ? group("div", "run-list nested", ...runs.map(runRow)) : empty("No runs yet."));
    const receipts = array(detail.receipts).filter(record);
    if (receipts.length) {
      parts.push(node("h4", "Applies"), group("div", "table-scroll", table(["Outcome", "Host", "Started", "Changed", "Receipt"], receipts.map((item) => [
        group("span", "cell-state", lamp(RUN_ASPECTS[item.status] || "dark", runWord(item.status)), node("span", runWord(item.status))),
        hostName(item.host_id), timestamp(item.started_at), `${array(item.changed_tasks).length} tasks`, node("span", text(item.id), "machine")]))));
    }
    return parts;
  }
  function renderRuns() {
    const runs = array(pb.runs);
    const active = activeRuns().length;
    const badge = byId("run-badge");
    badge.textContent = active ? `${active} running` : "";
    badge.hidden = !active;
    byId("runs-count").textContent = pb.runs ? `${runs.length} recent${active ? `, ${active} running` : ""}` : "";
    rerender(pbUi.runs, () => {
      if (!pb.runs) pbUi.runs.replaceChildren(empty("Loading runs."));
      else if (!runs.length) pbUi.runs.replaceChildren(empty("No runs yet."));
      else pbUi.runs.replaceChildren(...runs.slice(0, 20).map(runRow));
    });
  }
  function runRow(run) {
    const status = text(run.status);
    const progress = record(run.progress) ? run.progress : {};
    const now = RUN_ACTIVE.has(status) ? (progress.task ? `Now: ${progress.task}` : sentence(text(run.phase, "starting"))) : text(run.error, "");
    return group("div", "run-row",
      group("span", "cell-state", lamp(RUN_ASPECTS[status] || "dark", runWord(status)), node("strong", runWord(status))),
      group("span", "run-what", node("span", `${run.kind === "apply" ? "Apply" : "Plan"} ${text(run.playbook_id)}`), node("span", `on ${hostName(run.host_id)}`, "row-sub")),
      group("span", "run-when", node("span", timestamp(run.created_at), "row-sub"), node("span", text(run.requested_by, ""), "row-sub")),
      node("span", now, RUN_ACTIVE.has(status) ? "run-now" : ["failed", "busy", "needs-inspection", "interrupted"].includes(status) ? "row-attention" : "row-sub"),
      button("Open", "quiet", `open-run:${run.id}`, () => openRun(run.id)));
  }

  // The run panel: a form for a new plan, then that run's live progress, the plan, the approval and the receipt.
  function closeRunner() {
    pb.runner = null;
    pbUi.run.hidden = true;
    pbUi.run.replaceChildren();
    if (window.location.hash.startsWith("#playbooks/")) window.history.replaceState(null, "", "#playbooks");
    schedulePlaybookPoll();
  }
  async function openRunner(playbookId, hostId = null, run = null) {
    const item = playbookById(playbookId);
    if (!item) { error(pbUi.error, `Playbook ${playbookId} is no longer registered.`); return; }
    const detail = await loadDetail(playbookId);
    const eligible = array(item.hosts).filter((host) => host.eligible);
    pb.runner = { playbookId, item, variables: array(detail?.discovery?.variables).filter(record), hostId: hostId || eligible[0]?.host_id || array(item.hosts)[0]?.host_id,
      runId: run?.id || null, run, plan: run?.plan || null, receipt: run?.receipt || null, fields: [], busy: false, applyFor: null };
    buildRunPanel();
    if (run) renderRunState();
    pbUi.run.hidden = false;
    byId("run-panel-title").focus();
    schedulePlaybookPoll();
  }
  async function openRun(runId) {
    try {
      const run = await api(`/api/ansible/runs/${encodeURIComponent(runId)}`);
      if (!pb.list) await loadPlaybooks();
      await openRunner(run.playbook_id, run.host_id, run);
      if (!playbookById(run.playbook_id)) return;
      window.history.replaceState(null, "", `#playbooks/${encodeURIComponent(runId)}`);
    } catch (cause) { error(pbUi.error, `Run ${runId}: ${cause.message}`); }
  }
  async function refreshRunner() {
    const runner = pb.runner;
    if (!runner?.runId) return;
    const run = await api(`/api/ansible/runs/${encodeURIComponent(runner.runId)}`);
    if (pb.runner !== runner) return;
    runner.run = run;
    if (run.plan) runner.plan = run.plan;
    if (run.receipt) runner.receipt = run.receipt;
    renderRunState();
  }
  function buildRunPanel() {
    const runner = pb.runner;
    const item = runner.item;
    const title = node("h3", `Run ${item.id}`);
    title.id = "run-panel-title";
    title.tabIndex = -1;
    const dom = runner.dom = {};
    const host = node("select");
    host.id = "run-host";
    array(item.hosts).forEach((entry) => {
      const option = node("option", `${hostName(entry.host_id)}${entry.eligible ? "" : " (cannot run)"}`);
      option.value = entry.host_id;
      option.disabled = !entry.eligible;
      host.append(option);
    });
    host.value = runner.hostId || "";
    dom.variables = node("div", undefined, "var-fields");
    dom.sudo = node("div", undefined, "sudo-box");
    const form = node("form", undefined, "operation-form run-form");
    form.noValidate = true;
    form.setAttribute("aria-label", `Plan ${item.id}`);
    dom.plan = button("Plan (check mode)", "primary", "plan-submit");
    dom.plan.type = "submit";
    form.append(field("Host", host), dom.variables);
    const repo = record(item.repo_state) ? item.repo_state : {};
    if (repo.dirty) {
      dom.dirty = node("input");
      dom.dirty.type = "checkbox";
      form.append(group("label", "check-label", dom.dirty, node("span", "Plan the uncommitted working tree (recorded in the plan and receipt)")));
    }
    form.append(dom.sudo, group("div", "shell-actions", dom.plan));
    form.addEventListener("submit", submitPlan);
    host.addEventListener("change", () => { runner.hostId = host.value; fillRunFields(); });
    dom.form = form;
    dom.progress = node("div", undefined, "run-progress");
    dom.progress.setAttribute("aria-live", "polite");
    dom.result = node("div", undefined, "run-result");
    dom.apply = node("div", undefined, "run-apply");
    dom.receipt = node("div", undefined, "run-receipt");
    dom.status = node("p", "", "status-line");
    dom.status.setAttribute("role", "status");
    dom.error = node("p", "", "error-message");
    dom.error.setAttribute("role", "alert");
    dom.error.hidden = true;
    pbUi.run.replaceChildren(group("div", "side-head", title, button("Close", "quiet", null, closeRunner)),
      node("p", `${CHECK_TRUST[item.check_mode] || ""} A plan holds ${hostName(runner.hostId)}'s lease while it runs and changes nothing on purpose.`, "section-note"),
      form, dom.status, dom.error, dom.progress, dom.result, dom.apply, dom.receipt);
    fillRunFields();
  }
  function fillRunFields() {
    const runner = pb.runner;
    const allowed = runner.variables.filter((v) => v.overridable);
    runner.fields = allowed.map((v) => varField(v, runner.hostId));
    runner.dom.variables.replaceChildren(...(allowed.length
      ? [node("h4", "Variables"), node("p", `Filled in with what ${hostName(runner.hostId)} gets today. Only values you change are sent, and recorded with the plan, except secret ones.`, "field-note"), ...runner.fields.map((item) => item.element)]
      : [node("p", "This registration allows no variable overrides. Edit it to choose some.", "field-note")]));
    runner.dom.sudo.replaceChildren(...sudoFields(runner.item, runner.hostId, "plan"));
  }
  // The password field: shown when the playbook uses sudo and the host has no passwordless sudo (or it is not known yet).
  function sudoFields(item, hostId, purpose) {
    const runner = pb.runner;
    if (!item.become) { runner.dom[`${purpose}Password`] = null; return []; }
    const state = purpose === "apply" ? (runner.plan?.preflight?.passwordless_sudo === false ? "password" : "passwordless") : sudoState(item, hostId);
    if (state === "passwordless") {
      runner.dom[`${purpose}Password`] = null;
      return purpose === "plan" ? [node("p", `${hostName(hostId)} had passwordless sudo when last checked. The plan checks again.`, "field-note")] : [];
    }
    const input = node("input");
    Object.assign(input, { type: "password", autocomplete: "off", maxLength: 1024, spellcheck: false });
    input.id = `${purpose}-become-password`;
    input.setAttribute("autocapitalize", "none");
    runner.dom[`${purpose}Password`] = input;
    const note = purpose === "apply" ? "Asked again for the apply: it is never carried over from the plan. Sent once with this request, used for this run only, never stored."
      : state === "password" ? `${hostName(hostId)} has no passwordless sudo. Sent once with this request, used for this run only, never stored. sudo gets one attempt; a wrong password is not retried.`
        : `Not yet known whether ${hostName(hostId)} has passwordless sudo. Leave this empty to find out: the plan then stops before the check.`;
    return [field(`sudo password for ${hostName(hostId)}`, input, note),
      node("p", "Prefer your own terminal? Leave it empty: a plan without the password stops before the check run and gives you the leased commands to run yourself.", "field-note")];
  }
  function varField(v, hostId, prefix = "var") {
    const entry = v.effective?.[hostId];
    const known = entry && !entry.hidden && !entry.templated;
    const start = known ? entry.value : undefined;
    const element = node("div", undefined, "var-field");
    const id = `${prefix}-${v.name}`;
    const label = node("label", undefined, "var-label");
    label.htmlFor = id;
    label.append(node("span", v.name, "machine"), node("span", ` ${typeLabel(v)}`, "row-sub inline"));
    const notes = [];
    if (v.description) notes.push(v.description);
    if (v.secret) notes.push("Secret: sent for this run only, never stored or shown. Type it again for the apply.");
    else if (entry?.templated) notes.push(`Today: ${valueText(entry.value)} (a template, evaluated on the host). Leave empty to keep it.`);
    else if (entry) notes.push(`From ${entry.source}, ${entry.origin}.`);
    let control;
    let read;
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    if (v.secret) {
      control = node("input");
      Object.assign(control, { type: "password", autocomplete: "off", spellcheck: false });
      read = () => {
        if (!control.value) return { changed: false };
        if (["str", "path"].includes(v.type)) return { changed: true, value: control.value };
        try { return { changed: true, value: JSON.parse(control.value) }; } catch (cause) { throw new Error(`${v.name}: give a ${v.type} value as JSON.`); }
      };
    } else if (v.type === "bool" && typeof start === "boolean") {
      control = node("input");
      control.type = "checkbox";
      control.checked = start;
      read = () => ({ changed: control.checked !== start, value: control.checked });
    } else if (Array.isArray(v.choices) || v.type === "bool") {
      const choices = Array.isArray(v.choices) ? v.choices : [true, false];
      control = node("select");
      const keep = node("option", start === undefined ? "Keep as is" : `${valueText(start)} (current)`);
      keep.value = "";
      control.append(keep);
      choices.forEach((choice, index) => {
        if (start !== undefined && same(choice, start)) return;
        const option = node("option", valueText(choice));
        option.value = String(index);
        control.append(option);
      });
      read = () => control.value === "" ? { changed: false } : { changed: true, value: choices[Number(control.value)] };
    } else if (v.type === "int" || v.type === "float") {
      control = node("input");
      control.type = "number";
      control.step = v.type === "int" ? "1" : "any";
      control.inputMode = v.type === "int" ? "numeric" : "decimal";
      if (typeof start === "number") control.value = String(start);
      read = () => {
        if (control.value.trim() === "") return { changed: false };
        const value = Number(control.value);
        if (!Number.isFinite(value) || (v.type === "int" && !Number.isInteger(value))) throw new Error(`${v.name} must be ${v.type === "int" ? "a whole number" : "a number"}.`);
        return { changed: value !== start, value };
      };
    } else if (v.type === "list" && (!v.elements || ["str", "path", "int", "float"].includes(v.elements)) && (start === undefined || (Array.isArray(start) && start.every((item) => ["string", "number"].includes(typeof item))))) {
      const editor = listEditor(Array.isArray(start) ? start : [], v, id);
      control = editor.box;
      read = () => {
        const value = editor.read();
        return { changed: start === undefined ? value.length > 0 : !same(value, start), value };
      };
    } else if (["str", "path"].includes(v.type)) {
      control = node("input");
      control.autocomplete = "off";
      control.spellcheck = false;
      if (typeof start === "string") control.value = start;
      read = () => (start === undefined && control.value === "") ? { changed: false } : { changed: control.value !== start, value: control.value };
    } else {
      control = node("textarea");
      control.rows = 3;
      control.spellcheck = false;
      if (start !== undefined) control.value = JSON.stringify(start, null, 2);
      read = () => {
        if (control.value.trim() === "") return { changed: false };
        let value;
        try { value = JSON.parse(control.value); } catch (cause) { throw new Error(`${v.name}: not valid JSON.`); }
        return { changed: !same(value, start), value };
      };
    }
    if (control.tagName !== "DIV") control.id = id;
    control.dataset.focusKey = id;
    if (control.type === "checkbox") element.append(group("label", "check-label", control, node("span", v.name, "machine"), node("span", typeLabel(v), "row-sub")));
    else element.append(label, control);
    notes.forEach((note) => element.append(node("span", note, "field-note")));
    return { name: v.name, secret: v.secret, element, read, control };
  }
  function listEditor(values, v, id) {
    const box = node("div", undefined, "list-editor");
    box.id = id;
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", `${v.name} items`);
    const items = node("ul", undefined, "list-items");
    const add = button("Add item", "quiet", `${id}:add`);
    const addItem = (value) => {
      const input = node("input");
      input.value = value === undefined ? "" : String(value);
      input.spellcheck = false;
      input.setAttribute("aria-label", `${v.name} item`);
      const li = node("li", undefined, "list-item");
      const remove = button("Remove", "quiet", null, () => {
        const next = li.nextElementSibling || li.previousElementSibling;
        li.remove();
        (next?.querySelector("input") || add).focus();
      });
      remove.setAttribute("aria-label", `Remove this ${v.name} item`);
      li.append(input, remove);
      items.append(li);
      return input;
    };
    values.forEach(addItem);
    add.addEventListener("click", () => addItem("").focus());
    box.append(items, add);
    const numeric = ["int", "float"].includes(v.elements) || values.some((item) => typeof item === "number");
    return { box, read: () => Array.from(items.querySelectorAll("input"), (input) => input.value.trim()).filter((item) => item !== "").map((item) => {
      if (!numeric) return item;
      const value = Number(item);
      if (!Number.isFinite(value) || (v.elements === "int" && !Number.isInteger(value))) throw new Error(`${v.name}: ${item} is not a ${v.elements === "int" ? "whole number" : "number"}.`);
      return value;
    }) };
  }
  function clearSecrets(runner) {
    runner.fields.filter((item) => item.secret).forEach((item) => { item.control.value = ""; });
    (runner.applySecrets || []).forEach((item) => { item.control.value = ""; });
    ["planPassword", "applyPassword"].forEach((key) => { if (runner.dom[key]) runner.dom[key].value = ""; });
  }
  async function submitPlan(event) {
    event.preventDefault();
    const runner = pb.runner;
    if (!runner || runner.busy) return;
    const dom = runner.dom;
    error(dom.error, "");
    const body = { playbook_id: runner.playbookId, host_id: runner.hostId, extra_vars: {} };
    try {
      runner.fields.forEach((item) => { const got = item.read(); if (got.changed) body.extra_vars[item.name] = got.value; });
    } catch (cause) {
      error(dom.error, cause.message);
      return;
    }
    if (dom.dirty?.checked) body.allow_dirty = true;
    if (dom.planPassword?.value) body.become_password = dom.planPassword.value;
    clearSecrets(runner);  // Out of the page as soon as the request is built; failures do not bring it back.
    runner.busy = true;
    dom.plan.disabled = true;
    dom.status.textContent = `Starting a plan of ${runner.playbookId} on ${hostName(runner.hostId)}…`;
    try {
      const run = await api("/api/ansible/plan", body, 330000);
      Object.assign(runner, { runId: run.id, run, plan: null, receipt: null, applyFor: null });
      window.history.replaceState(null, "", `#playbooks/${encodeURIComponent(run.id)}`);
      dom.status.textContent = `Plan running (run ${run.id}). It continues if you close this page.`;
      pb.runs = [run, ...array(pb.runs).filter((item) => item.id !== run.id)];
      renderRuns();
      renderRunState();
    } catch (cause) {
      error(dom.error, cause.message);
      dom.status.textContent = "The plan did not start.";
    } finally {
      delete body.become_password;
      delete body.extra_vars;
      runner.busy = false;
      dom.plan.disabled = false;
      schedulePlaybookPoll();
    }
  }
  function taskNote(task) {
    return [task.status, task.diff_bytes ? "has a diff" : "", task.not_predicted ? "not predicted in check mode" : "",
      task.forced_run ? "ran for real during the check" : "", task.handler ? "handler" : "", task.msg ? task.msg : ""].filter(Boolean).join(" · ");
  }
  function progressView(run) {
    const progress = record(run.progress) ? run.progress : {};
    const tasks = array(progress.tasks).filter(record);
    const active = RUN_ACTIVE.has(run.status);
    const parts = [node("h4", `${run.kind === "apply" ? "Apply" : "Plan"} on ${hostName(run.host_id)}`),
      group("p", "run-headline", lamp(RUN_ASPECTS[run.status] || "dark", runWord(run.status)), node("strong", runWord(run.status)),
        node("span", active ? (progress.task ? ` Now: ${progress.task}` : ` ${sentence(text(run.phase, "starting"))}`) : "", "row-sub inline"))];
    if (!active && run.error) parts.push(node("p", run.error, run.status === "planned" || run.status === "succeeded" ? "row-sub" : "row-attention"));
    if (run.become_password) parts.push(node("p", `sudo: ${run.become_password}.`, "row-sub"));
    if (tasks.length) {
      const steps = node("ol", undefined, "task-list");
      tasks.forEach((task) => steps.append(group("li", `task is-${text(task.status, "unknown")}`, lamp(TASK_ASPECTS[task.status] || "dark", text(task.status)),
        node("span", text(task.task, "Unnamed task")), node("span", taskNote(task), "row-sub"))));
      parts.push(steps);
      if (progress.truncated) parts.push(node("p", "Earlier tasks are not shown.", "field-note"));
    }
    return parts;
  }
  function planView(plan) {
    const check = record(plan.check) ? plan.check : {};
    const values = record(plan.extra_vars?.values) ? plan.extra_vars.values : {};
    const privilege = plan.become_password ? `sudo: ${plan.become_password}` : plan.preflight?.passwordless_sudo ? "Passwordless sudo"
      : plan.playbook?.become ? "Needs the sudo password" : "No sudo";
    const parts = [node("h4", "Plan"), metadata([
      ["Status", group("span", "cell-state", lamp(RUN_ASPECTS[plan.status] || "dark", runWord(plan.status)), node("span", runWord(plan.status)))],
      ["Plan ID", node("span", text(plan.id), "machine")],
      ["Commit", node("span", `${text(plan.repo?.commit)}${plan.repo?.dirty ? " plus uncommitted changes (allowed)" : ""}`, "machine")],
      ["Expires", timestamp(plan.expires_at)],
      ["Overrides", Object.keys(values).length || strings(plan.extra_vars?.secret_names).length
        ? [...Object.entries(values).map(([name, value]) => `${name} = ${valueText(value)}`), ...strings(plan.extra_vars?.secret_names).map((name) => `${name} (secret, not recorded)`)].join("; ") : "None"],
      ["Privilege", privilege], ["ansible-core", text(plan.ansible_core)],
    ])];
    const blockers = strings(plan.blockers);
    if (blockers.length) parts.push(group("div", "blocker-box", node("strong", "Not applicable"), list(blockers, "")));
    if (check.ran) {
      parts.push(node("h4", "Would change"), list(strings(check.changed_tasks), "No task reported a change."));
      if (strings(check.not_predicted).length) parts.push(node("h4", "Not predicted"), list(strings(check.not_predicted), ""));
      if (strings(check.forced_run).length) parts.push(node("h4", "Ran for real during the check"), list(strings(check.forced_run), ""));
      if (strings(check.failed_tasks).length) parts.push(node("h4", "Failed"), list(strings(check.failed_tasks), ""));
    } else if (check.reason) parts.push(node("p", check.reason, "row-attention"));
    parts.push(node("p", CHECK_TRUST[plan.playbook?.check_mode] || "", "field-note"));
    return parts;
  }
  function commandBlock(label, command) {
    const pre = node("pre", command, "evidence command");
    pre.tabIndex = 0;
    const copy = button("Copy", "quiet");
    copy.setAttribute("aria-label", `Copy the ${label.toLocaleLowerCase()} command`);
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(command);
        copy.textContent = "Copied";
      } catch (cause) {
        const range = document.createRange();
        range.selectNodeContents(pre);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        copy.textContent = "Selected; copy with Ctrl+C";
      }
      window.setTimeout(() => { copy.textContent = "Copy"; }, 2500);
    });
    return group("div", "command-block", group("div", "command-head", node("strong", label), copy), pre);
  }
  function operatorPath(plan) {
    const commands = record(plan.operator_commands) ? plan.operator_commands : {};
    const request = node("input");
    Object.assign(request, { value: crypto.randomUUID(), maxLength: 128, autocomplete: "off", spellcheck: false, className: "machine" });
    const record_ = button("Record my terminal run", "secondary", "record-manual", async () => {
      record_.disabled = true;
      error(pb.runner.dom.error, "");
      try {
        const receipt = await api(`/api/ansible/plans/${encodeURIComponent(plan.id)}/record-manual`, { request_id: request.value.trim() });
        pb.runner.receipt = receipt;
        pb.runner.dom.receipt.replaceChildren(...receiptView(receipt));
        refreshReceipts();
      } catch (cause) { error(pb.runner.dom.error, cause.message); }
      finally { record_.disabled = false; }
    });
    return [node("h4", "Or run it in your own terminal"),
      node("p", "These commands hold the host's lease, use this plan's inventory and the pinned runner, and ask for the sudo password in your terminal. Run the check, then the apply, then record it here.", "field-note"),
      commandBlock("Check", text(commands.check, "")), commandBlock("Apply", text(commands.apply, "")),
      field("Request ID for the record", request, "Identifies the receipt. Sending the same ID again returns the first one."),
      group("div", "shell-actions", record_)];
  }
  function receiptView(receipt) {
    return [node("h4", "Receipt"), metadata([
      ["Outcome", group("span", "cell-state", lamp(RUN_ASPECTS[receipt.status] || "dark", runWord(receipt.status)), node("span", runWord(receipt.status)))],
      ["Receipt ID", node("span", text(receipt.id), "machine")], ["Request ID", node("span", text(receipt.request_id), "machine")],
      ["Commit", node("span", text(receipt.commit), "machine")], ["Ran by", receipt.executor === "operator" ? "You, in your terminal" : "Switchyard"],
      ["Finished", timestamp(receipt.finished_at)],
    ]), receipt.error ? node("p", receipt.error, "row-attention") : null,
    node("h4", "Changed"), list(strings(receipt.changed_tasks), "No task reported a change."),
    strings(receipt.failed_tasks).length ? node("h4", "Failed") : null, strings(receipt.failed_tasks).length ? list(strings(receipt.failed_tasks), "") : null,
    group("div", "body-actions", button("Show in the Audit log", "quiet", null, () => { selectTab("receipts", true); refreshReceipts(); }))].filter(Boolean);
  }
  function applyBox(plan) {
    const runner = pb.runner;
    const box = node("div", undefined, "approval run-approval");
    const approve = node("input");
    approve.type = "checkbox";
    approve.id = "approve-ansible";
    const request = node("input");
    Object.assign(request, { value: crypto.randomUUID(), maxLength: 128, autocomplete: "off", spellcheck: false, className: "machine" });
    runner.applySecrets = strings(plan.extra_vars?.secret_names).map((name) => {
      const v = runner.variables.find((item) => item.name === name) || { name, type: "str", secret: true };
      return varField({ ...v, secret: true }, plan.host_id, "apply-var");
    });
    const submit = button("Apply approved plan", "primary", "apply-submit");
    submit.disabled = true;
    approve.addEventListener("change", () => { submit.disabled = !approve.checked; });
    submit.addEventListener("click", () => submitApply(plan, approve, request, submit));
    box.append(node("h4", "Approve"), group("label", "approval-label", approve, node("span", `I approve applying this exact plan to ${hostName(plan.host_id)}.`)),
      field("Request ID", request, "Identifies this apply. Sending the same ID again returns the first result instead of running twice."),
      ...runner.applySecrets.map((item) => item.element), ...sudoFields(runner.item, plan.host_id, "apply"), submit);
    return box;
  }
  async function submitApply(plan, approve, request, submit) {
    const runner = pb.runner;
    if (!runner || runner.busy || !approve.checked) return;
    const dom = runner.dom;
    error(dom.error, "");
    const body = { plan_id: plan.id, approved: true, request_id: request.value.trim() };
    try {
      const secrets = {};
      runner.applySecrets.forEach((item) => {
        const got = item.read();
        if (!got.changed) throw new Error(`Type ${item.name} again for the apply.`);
        secrets[item.name] = got.value;
      });
      if (Object.keys(secrets).length) body.secret_vars = secrets;
      if (dom.applyPassword && !dom.applyPassword.value) throw new Error(`Type the sudo password for ${hostName(plan.host_id)}: it is asked again for every run.`);
      if (dom.applyPassword) body.become_password = dom.applyPassword.value;
    } catch (cause) {
      clearSecrets(runner);
      error(dom.error, cause.message);
      return;
    }
    clearSecrets(runner);
    runner.busy = true;
    submit.disabled = true;
    dom.status.textContent = "Starting the apply…";
    try {
      const result = await api("/api/ansible/apply", body, 330000);
      if (result.kind === "ansible-apply") {
        runner.receipt = result;
        dom.receipt.replaceChildren(...receiptView(result));
        dom.status.textContent = "This request ID was already used: showing its receipt. Nothing ran again.";
      } else {
        Object.assign(runner, { runId: result.id, run: result, receipt: null });
        window.history.replaceState(null, "", `#playbooks/${encodeURIComponent(result.id)}`);
        dom.status.textContent = `Apply running (run ${result.id}). It continues if you close this page.`;
        pb.runs = [result, ...array(pb.runs).filter((item) => item.id !== result.id)];
        renderRuns();
        renderRunState();
      }
    } catch (cause) {
      error(dom.error, cause.message);
      dom.status.textContent = "The apply did not start. Check the Audit log before trying again.";
      submit.disabled = !approve.checked;
    } finally {
      delete body.become_password;
      delete body.secret_vars;
      runner.busy = false;
      schedulePlaybookPoll();
    }
  }
  function renderRunState() {
    const runner = pb.runner;
    if (!runner) return;
    const { run, plan, dom } = runner;
    dom.progress.replaceChildren(...(run ? progressView(run) : []));
    if (run && RUN_ACTIVE.has(run.status)) dom.status.textContent = `${run.kind === "apply" ? "Apply" : "Plan"} running. It continues if you close this page.`;
    else if (run) dom.status.textContent = "";
    // A run in the panel replaces the form; "New plan…" brings the form back for this playbook.
    dom.form.hidden = Boolean(run);
    const again = run && !RUN_ACTIVE.has(run.status) ? group("div", "body-actions", button("New plan…", "quiet", "new-plan", () => {
      Object.assign(runner, { runId: null, run: null, plan: null, receipt: null, applyFor: null });
      window.history.replaceState(null, "", "#playbooks");
      dom.apply.replaceChildren();
      renderRunState();
      fillRunFields();
      byId("run-host").focus();
    })) : null;
    dom.result.replaceChildren(...(plan ? planView(plan) : []), ...(again ? [again] : []));
    const expired = plan && Date.parse(plan.expires_at) <= Date.now();
    if (plan && plan.applicable && !plan.consumed_by && !expired && run?.kind !== "apply") {
      if (runner.applyFor !== plan.id) {
        runner.applyFor = plan.id;
        dom.apply.replaceChildren(applyBox(plan),
          ...(runner.item.become ? [node("p", `Or apply it from your own terminal: switchyard ansible apply ${plan.id} --approve --request-id <ID>${runner.item.become ? " --ask-become-pass" : ""}`, "field-note machine")] : []));
      }
    } else if (plan?.status === "needs-operator-privilege" && !plan.consumed_by) {
      if (runner.applyFor !== `operator:${plan.id}`) {
        runner.applyFor = `operator:${plan.id}`;
        dom.apply.replaceChildren(...operatorPath(plan));
      }
    } else {
      runner.applyFor = null;
      dom.apply.replaceChildren(...(plan && expired && plan.applicable && !plan.consumed_by ? [node("p", "This plan expired. Plan again to apply.", "row-attention")] : []));
    }
    const receipt = run?.receipt || runner.receipt;
    dom.receipt.replaceChildren(...(receipt ? receiptView(receipt) : []));
  }

  // The registration editor: read a directory, choose what to register, save with a revision check.
  function closeEditor() {
    pb.editor = null;
    pbUi.editor.hidden = true;
    pbUi.editor.replaceChildren();
  }
  function openEditor(mode, id = null) {
    const item = id ? playbookById(id) : null;
    pb.editor = { mode, id, item, inspection: null, busy: false };
    const title = node("h3", mode === "add" ? "Add playbook" : `Edit ${id}`);
    title.id = "playbook-editor-title";
    title.tabIndex = -1;
    const path = node("input");
    Object.assign(path, { id: "playbook-repo", maxLength: 1024, autocomplete: "off", spellcheck: false, placeholder: "~/Repos/my-playbooks", className: "machine" });
    path.value = item ? text(item.repo, "") : "";
    const inspect = button("Read directory", "secondary", "inspect-repo");
    inspect.type = "submit";
    const form = node("form", undefined, "operation-form");
    form.noValidate = true;
    form.append(field("Repository directory", path, "A Git work tree in your home directory, owned by you. Switchyard reads it without running anything."), group("div", "shell-actions", inspect));
    const fields = node("div", undefined, "registration-fields");
    const status = node("p", "", "status-line");
    status.setAttribute("role", "status");
    const problem = node("p", "", "error-message");
    problem.setAttribute("role", "alert");
    problem.hidden = true;
    pb.editor.dom = { path, inspect, fields, status, problem };
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (pb.editor.busy) return;
      pb.editor.busy = true;
      inspect.disabled = true;
      error(problem, "");
      status.textContent = "Reading the directory…";
      try {
        pb.editor.inspection = await api("/api/ansible/inspect", { path: path.value.trim() }, 330000);
        status.textContent = `Read ${pb.editor.inspection.path}.`;
        fillRegistration();
      } catch (cause) {
        error(problem, cause.message);
        status.textContent = "";
        fields.replaceChildren();
      } finally { pb.editor.busy = false; inspect.disabled = false; }
    });
    pbUi.editor.replaceChildren(group("div", "side-head", title, button("Close editor", "quiet", null, closeEditor)),
      node("p", "The registration is stored in this desk's database. It decides where the playbook may run and which variables you may set per run.", "section-note"),
      form, status, problem, fields);
    pbUi.editor.hidden = false;
    (mode === "edit" ? inspect : path).focus();
    if (mode === "edit") form.requestSubmit();
  }
  function fillRegistration() {
    const editor = pb.editor;
    const found = editor.inspection;
    const item = editor.item;
    const dom = editor.dom;
    const parts = [];
    const git = record(found.git) ? found.git : {};
    parts.push(node("p", git.repository ? `Git commit ${shortCommit(git.commit)}${git.dirty ? ", with uncommitted changes" : ", clean"}.` : `Not usable: ${text(git.error, "not a Git work tree")}.`, git.repository && !git.dirty ? "field-note" : "row-attention"));
    const playbooks = array(found.playbooks).filter(record);
    if (!playbooks.length) {
      parts.push(empty("No playbook files found at the top of this directory or in playbooks/."));
      dom.fields.replaceChildren(...parts);
      return;
    }
    const id = node("input");
    Object.assign(id, { id: "playbook-id", maxLength: 64, pattern: "[a-z0-9][a-z0-9-]{0,63}", autocomplete: "off", spellcheck: false, className: "machine" });
    id.value = item ? item.id : text(found.path.split("/").pop(), "").toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+/, "").slice(0, 64);
    id.disabled = editor.mode === "edit";
    const description = node("textarea");
    Object.assign(description, { id: "playbook-description", rows: 3, maxLength: 2048 });
    description.value = item ? text(item.description, "") : "";
    const playbook = node("select");
    playbook.id = "playbook-file";
    playbooks.forEach((entry) => {
      const option = node("option", `${entry.path} (${array(entry.plays).length} ${array(entry.plays).length === 1 ? "play" : "plays"})`);
      option.value = entry.path;
      playbook.append(option);
    });
    playbook.value = item && playbooks.some((entry) => entry.path === item.playbook) ? item.playbook : playbooks[0].path;
    const inventory = node("select");
    inventory.id = "playbook-inventory";
    const none = node("option", "None (Switchyard's connection settings only)");
    none.value = "";
    inventory.append(none);
    array(found.inventories).filter(record).forEach((entry) => {
      const option = node("option", entry.error ? `${entry.path} (unreadable)` : `${entry.path} (groups ${strings(entry.groups).join(", ") || "none"})`);
      option.value = entry.path;
      inventory.append(option);
    });
    inventory.value = item ? text(item.inventory, "") : array(found.inventories).find((entry) => !entry.error)?.path || "";
    const groups = node("input");
    Object.assign(groups, { id: "playbook-groups", maxLength: 1024, autocomplete: "off", spellcheck: false });
    const become = node("input");
    become.type = "checkbox";
    become.id = "playbook-become";
    const checkMode = node("select");
    checkMode.id = "playbook-check-mode";
    Object.entries(CHECK_TRUST).forEach(([value, label]) => { const option = node("option", label); option.value = value; checkMode.append(option); });
    checkMode.value = item ? item.check_mode : "partial";
    const hosts = node("fieldset", undefined, "host-choices");
    const hostBoxes = new Map();
    hosts.append(node("legend", "May run on"), node("p", "Registry hosts reached over SSH. The playbook can run on these only.", "field-note"));
    const choices = node("ul", undefined, "host-choice-list");
    strings(found.ssh_hosts).forEach((hostId) => {
      const box = node("input");
      box.type = "checkbox";
      box.value = hostId;
      hostBoxes.set(hostId, box);
      const name = hostName(hostId);
      const choice = group("label", "check-label", box, node("span", name));
      if (name !== hostId) choice.append(node("span", hostId, "machine row-sub"));
      choices.append(group("li", "", choice));
    });
    hosts.append(strings(found.ssh_hosts).length ? choices : empty("No SSH hosts in the registry."));
    const variables = node("div", undefined, "registration-vars");
    const save = button(editor.mode === "add" ? "Register playbook" : "Save changes", "primary", "save-registration");
    const chosen = { allowed: new Set(strings(item?.extra_vars_allowed)), secret: new Set(strings(item?.secret_vars)) };
    const fillPlaybook = (initial) => {
      const entry = playbooks.find((candidate) => candidate.path === playbook.value) || playbooks[0];
      const inv = array(found.inventories).find((candidate) => candidate.path === inventory.value);
      if (!initial || !item) {
        const patterns = array(entry.plays).flatMap((play) => text(play.hosts, "").split(/[:,&!\s]+/)).filter((name) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !["all", "ungrouped"].includes(name));
        groups.value = (inv ? patterns.filter((name) => strings(inv.groups).includes(name)) : patterns).join(", ") || strings(inv?.groups)[0] || "";
        become.checked = array(entry.plays).some((play) => play.become);
        hostBoxes.forEach((box, hostId) => { box.checked = strings(inv?.registry_hosts).includes(hostId); });
      } else {
        groups.value = strings(item.groups).join(", ");
        become.checked = item.become === true;
        hostBoxes.forEach((box, hostId) => { box.checked = strings(item.allowed_hosts).includes(hostId); });
      }
      const vars = array(entry.variables).filter(record);
      const rows = vars.map((v) => {
        const allow = node("input");
        allow.type = "checkbox";
        allow.checked = chosen.allowed.has(v.name);
        allow.setAttribute("aria-label", `Allow overriding ${v.name}`);
        allow.addEventListener("change", () => { if (allow.checked) chosen.allowed.add(v.name); else chosen.allowed.delete(v.name); });
        const secret = node("input");
        secret.type = "checkbox";
        secret.checked = v.secret || chosen.secret.has(v.name);
        secret.disabled = v.secret === true;
        secret.title = v.secret ? strings(v.secret_reasons).join("; ") : "";
        secret.setAttribute("aria-label", `Treat ${v.name} as secret`);
        secret.addEventListener("change", () => { if (secret.checked) chosen.secret.add(v.name); else chosen.secret.delete(v.name); });
        return [node("span", v.name, "machine"), typeLabel(v), allow, secret, text(v.description, "")];
      });
      variables.replaceChildren(node("h4", "Variables"),
        node("p", "Tick the variables the operator may set for a run. Secret values are sent for one run and never stored; no_log, private prompts and vaulted values are always secret.", "field-note"),
        vars.length ? group("div", "table-scroll", table(["Variable", "Type", "May override", "Secret", "Description"], rows)) : empty("No variables found in this playbook."));
    };
    playbook.addEventListener("change", () => fillPlaybook(false));
    inventory.addEventListener("change", () => fillPlaybook(false));
    fillPlaybook(true);
    save.addEventListener("click", () => saveRegistration({ id, description, playbook, inventory, groups, become, checkMode, hostBoxes, chosen, save }));
    parts.push(group("div", "operation-fields",
      field("Playbook ID", id, editor.mode === "add" ? "Lowercase letters, digits and hyphens. Cannot change later." : `Revision ${item.revision}.`),
      field("Playbook file", playbook), field("Inventory", inventory, "Its host and group variables reach the run; its connection settings never do.")),
      field("Description", description),
      field("Groups the host joins", groups, "Comma-separated, so the play's hosts: pattern matches the generated inventory."),
      hosts, group("label", "check-label", become, node("span", "The playbook uses sudo (become)")),
      field("Check mode", checkMode, "How far a plan can be trusted to predict the apply."),
      variables, group("div", "shell-actions", save));
    dom.fields.replaceChildren(...parts);
  }
  async function saveRegistration(form) {
    const editor = pb.editor;
    if (!editor || editor.busy) return;
    const registration = {
      description: form.description.value.trim(), repo: editor.inspection.path, playbook: form.playbook.value,
      groups: form.groups.value.split(",").map((value) => value.trim()).filter(Boolean),
      allowed_hosts: Array.from(form.hostBoxes).filter(([, box]) => box.checked).map(([hostId]) => hostId),
      become: form.become.checked, check_mode: form.checkMode.value,
      extra_vars_allowed: Array.from(form.chosen.allowed).sort(), secret_vars: Array.from(form.chosen.secret).sort(),
    };
    if (form.inventory.value) registration.inventory = form.inventory.value;
    const problems = [!registration.description && "Write a description.", !registration.groups.length && "Name at least one group.",
      !registration.allowed_hosts.length && "Choose at least one host.", editor.mode === "add" && !/^[a-z0-9][a-z0-9-]{0,63}$/.test(form.id.value) && "The playbook ID uses lowercase letters, digits and hyphens."].filter(Boolean);
    error(editor.dom.problem, problems.join(" "));
    if (problems.length) return;
    editor.busy = true;
    form.save.disabled = true;
    try {
      const saved = editor.mode === "add"
        ? await api("/api/ansible/playbooks", { playbook_id: form.id.value, registration })
        : await api(`/api/ansible/playbooks/${encodeURIComponent(editor.id)}/update`, { registration, expected_revision: editor.item.revision });
      pbUi.status.textContent = `${editor.mode === "add" ? "Registered" : "Saved"} ${saved.id}, revision ${saved.revision}.`;
      opened.add(`playbook:${saved.id}`);
      pb.details.delete(saved.id);
      closeEditor();
      await loadPlaybooks();
      focusKey(pbUi.list, `summary:playbook:${saved.id}`);
    } catch (cause) {
      error(editor.dom.problem, cause.message);
    } finally {
      if (pb.editor === editor) { editor.busy = false; form.save.disabled = false; }
    }
  }
  async function removePlaybook(item) {
    if (pb.busy) return;
    pb.busy = true;
    renderPlaybooks();
    try {
      await api(`/api/ansible/playbooks/${encodeURIComponent(item.id)}/remove`, { expected_revision: item.revision });
      pbUi.status.textContent = `Removed the registration of ${item.id}. Its plans and receipts stay.`;
      pb.confirm = null;
      pb.details.delete(item.id);
    } catch (cause) { error(pbUi.error, cause.message); }
    finally {
      pb.busy = false;
      await loadPlaybooks();
      byId("playbooks-title").focus();
    }
  }

  // --- LAN URLs ---
  // Web names lead through the gateway; DNS-only A/AAAA records do not. Both use the same
  // plan, approval and resumable apply flow. Only checked web routes become URL links.
  const LAN_APPLY_MS = 15 * 60 * 1000;
  const LAN_POLL_MS = 5000;
  const LAN_HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const LAN_ACTIONS = { create: "Publish", update: "Edit", delete: "Remove", resume: "Resume",
    "dns-create": "Add DNS record", "dns-update": "Edit DNS record", "dns-delete": "Remove DNS record" };
  const lan = { data: null, loading: false, timer: null, mode: null, route: null, from: null, plan: null, planBody: null,
    planRevision: null, result: null, busy: false, applying: false, endpointSignature: "" };
  const lanUi = {
    list: byId("lan-url-list"), pending: byId("lan-pending"), count: byId("lan-url-count"), search: byId("lan-url-search"),
    publish: byId("publish-lan-url"), addDns: byId("add-lan-dns"), refresh: byId("refresh-lan-urls"), viewer: byId("lan-urls-viewer"),
    dnsList: byId("lan-dns-list"), dnsCount: byId("lan-dns-count"), availability: byId("lan-urls-availability"),
    status: byId("lan-urls-status"), error: byId("lan-urls-error"), endpoints: byId("lan-endpoint-list"), endpointCount: byId("lan-endpoint-count"),
    editor: byId("lan-url-editor"), title: byId("lan-url-editor-title"), note: byId("lan-url-editor-note"), close: byId("close-lan-url-editor"),
    form: byId("lan-url-form"), hostnameField: byId("lan-url-hostname-field"), hostname: byId("lan-url-hostname"),
    hostnameNote: byId("lan-url-hostname-note"), hostnameError: byId("lan-url-hostname-error"),
    endpointField: byId("lan-url-endpoint-field"), endpoint: byId("lan-url-endpoint"), endpointError: byId("lan-url-endpoint-error"),
    addressField: byId("lan-dns-address-field"), address: byId("lan-dns-address"), addressError: byId("lan-dns-address-error"),
    submit: byId("plan-lan-url"), formStatus: byId("lan-url-status"), formError: byId("lan-url-form-error"), plan: byId("lan-url-plan"),
    approval: byId("lan-url-approval"), approve: byId("approve-lan-url"), approveText: byId("approve-lan-url-text"),
    requestId: byId("lan-url-request-id"), approvalNote: byId("lan-url-approval-note"), apply: byId("apply-lan-url"), result: byId("lan-url-result"),
  };
  const lanRoutes = () => array(lan.data?.routes).filter(record);
  const lanDnsRecords = () => array(lan.data?.dns_records).filter(record);
  const lanDnsAction = (mode) => typeof mode === "string" && mode.startsWith("dns-");
  const lanEndpoints = () => array(lan.data?.endpoints).filter(record);
  const lanPending = () => (record(lan.data?.pending) ? lan.data.pending : null);
  const lanConfigured = () => Boolean(lan.data) && lan.data.configured !== false;
  const canEditLan = () => isOperator() && fleet?.read_only_view !== true && lanConfigured();
  const canPlanLan = (mode) => canEditLan() && (mode === "resume" || (lanDnsAction(mode)
    ? lan.data?.dns_ready === true : lan.data?.ready !== false));
  const lanApplicable = (plan) => plan?.executable === true && !strings(plan.blockers).length;
  const endpointKey = (item) => JSON.stringify([text(item?.workload_id, ""), text(item?.endpoint_id, "")]);
  const workloadTitle = (id) => text(fleet?.workloads.find((item) => item.id === id)?.name, text(id));
  const lanName = (item) => text(item?.hostname, "unnamed");
  const lanProfile = (item) => text(item?.profile, "plain");
  function lanTarget(item) {
    const address = text(item?.address, "unknown");
    return `${text(item?.scheme, "http")}://${address.includes(":") && !address.startsWith("[") ? `[${address}]` : address}${number(item?.port) ? `:${item.port}` : ""}`;
  }
  function lanEndpointLabel(item) {
    return `${text(item?.endpoint_id)}: ${lanTarget(item)}${lanProfile(item) !== "plain" ? `, profile ${lanProfile(item)}` : ""}`;
  }
  // The zones already in use, to suggest the shape of a new name. The server decides which zones are allowed.
  function lanZones() {
    return [...new Set([...lanRoutes(), ...lanDnsRecords()].map((item) => lanName(item).split(".").slice(1).join(".")).filter(Boolean))].slice(0, 3);
  }
  // Only https to exactly the checked name, with no credentials, port, path, query or fragment, becomes a link.
  function lanHref(route) {
    const name = route?.hostname;
    if (typeof name !== "string" || !LAN_HOSTNAME.test(name) || typeof route.url !== "string") return null;
    let parsed;
    try { parsed = new URL(route.url); } catch (cause) { return null; }
    const plain = parsed.protocol === "https:" && parsed.hostname === name && !parsed.username && !parsed.password
      && !parsed.port && parsed.pathname === "/" && !parsed.search && !parsed.hash;
    return plain ? `https://${name}/` : null;
  }
  function lanLink(route, focusKey) {
    const href = lanHref(route);
    if (!href) return node("span", `${lanName(route)} (no link: the desk reported an unexpected URL)`, "row-attention inline");
    const link = node("a", route.hostname, "row-link machine");
    link.href = href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.title = `Open ${href} in a new tab`;
    if (focusKey) link.dataset.focusKey = focusKey;
    return link;
  }
  // Workload rows link the names published for them, from the cached fleet; this never reads the registry.
  function workloadLanLinks(id) {
    const routes = array(fleet?.lan_urls).filter((route) => record(route) && route.workload_id === id);
    if (!routes.length) return null;
    return group("span", "row-sub row-links", ...routes.map((route) => lanLink(route, `lan-of:${id}:${lanName(route)}`)));
  }
  function lanFieldError(input, note, message) {
    note.textContent = message;
    note.hidden = !message;
    if (message) input.setAttribute("aria-invalid", "true"); else input.removeAttribute("aria-invalid");
  }

  async function loadLanUrls(announce = false) {
    if (signedOut || pageClosed || lan.loading) return;
    lan.loading = true;
    lanUi.refresh.disabled = true;
    try {
      const data = await api("/api/lan-urls");
      lan.data = { ...data, routes: array(data.routes).filter(record), dns_records: array(data.dns_records).filter(record),
        endpoints: array(data.endpoints).filter(record), pending: record(data.pending) ? data.pending : null };
      error(lanUi.error, "");
      if (announce) lanUi.status.textContent = `LAN URLs read ${clock(Date.now())}.`;
    } catch (cause) {
      error(lanUi.error, cause.message);
    } finally {
      lan.loading = false;
      lanUi.refresh.disabled = false;
    }
    renderLanUrls();
    scheduleLanPoll();
  }
  // Re-read only while a change is running and someone is looking at this tab. Never in a hidden page.
  function scheduleLanPoll() {
    window.clearTimeout(lan.timer);
    lan.timer = null;
    if (pageClosed || document.hidden || signedOut || currentTab !== "lan-urls") return;
    if (!lan.applying && lanPending()?.status !== "running") return;
    lan.timer = window.setTimeout(() => { lan.timer = null; loadLanUrls(); }, LAN_POLL_MS);
  }

  function renderLanUrls() {
    const editable = canEditLan();
    const pending = lanPending();
    lanUi.publish.hidden = !editable;
    lanUi.addDns.hidden = !editable;
    lanUi.publish.disabled = !canPlanLan("create") || Boolean(pending) || lan.busy;
    lanUi.addDns.disabled = !canPlanLan("dns-create") || Boolean(pending) || lan.busy;
    lanUi.publish.title = pending ? "Finish or resume the unfinished change first." : !canPlanLan("create") ? "LAN URL publishing is not ready." : "";
    lanUi.addDns.title = pending ? "Finish or resume the unfinished change first." : !canPlanLan("dns-create") ? "DNS changes are not ready." : "";
    const unavailable = lanConfigured() ? [lan.data.ready === false ? "LAN URL changes are unavailable." : "",
      lan.data.dns_ready === false ? "DNS-only changes are unavailable." : "",
      lan.data.dns_sync_pending ? "Host registry DNS changes have not reached the DNS server yet." : ""].filter(Boolean).join(" ") : "";
    lanUi.availability.textContent = unavailable;
    lanUi.availability.hidden = !unavailable;
    const showViewer = !isOperator() && fleet?.read_only_view !== true && Boolean(auth) && lanConfigured();
    lanUi.viewer.hidden = !showViewer;
    lanUi.viewer.replaceChildren(...(showViewer ? ["Publishing, editing and removing LAN URLs or DNS records need the operator.",
      ...(canSignIn() ? [" ", signInButton("lan:sign-in")] : [])] : []));
    const routes = lanRoutes();
    const query = lanUi.search.value.trim().toLocaleLowerCase();
    const shown = routes.filter((route) => matches(route, query) || matches(workloadTitle(route.workload_id), query));
    lanUi.count.textContent = lanConfigured() ? `${shown.length === routes.length ? "" : `${shown.length} shown of `}${routes.length} published` : "";
    rerender(lanUi.pending, () => lanUi.pending.replaceChildren(...lanPendingView(pending)));
    rerender(lanUi.list, () => {
      if (!lan.data) lanUi.list.replaceChildren(empty(lanUi.error.hidden ? "Loading LAN URLs." : "LAN URLs could not be read. Reload to try again."));
      else if (!lanConfigured()) lanUi.list.replaceChildren(empty(text(lan.data.error, "LAN URLs are not configured on this desk.")));
      else if (!routes.length) lanUi.list.replaceChildren(empty(editable ? "No names are published yet. Publish LAN URL… gives a workload endpoint a name." : "No names are published yet."));
      else if (!shown.length) lanUi.list.replaceChildren(empty("No LAN URLs match. Clear the filter."));
      else lanUi.list.replaceChildren(...shown.map(lanRow));
    });
    const dnsRecords = lanDnsRecords();
    const shownDns = dnsRecords.filter((item) => matches(item, query) || (item.host_id && matches(hostName(item.host_id), query)));
    lanUi.dnsCount.textContent = lanConfigured() ? `${shownDns.length === dnsRecords.length ? "" : `${shownDns.length} shown of `}${dnsRecords.length} records` : "";
    rerender(lanUi.dnsList, () => {
      if (!lan.data) lanUi.dnsList.replaceChildren(empty(lanUi.error.hidden ? "Loading DNS records." : "DNS records could not be read. Reload to try again."));
      else if (!lanConfigured()) lanUi.dnsList.replaceChildren(empty(text(lan.data.error, "DNS is not configured on this desk.")));
      else if (!dnsRecords.length) lanUi.dnsList.replaceChildren(empty(editable ? "No DNS-only records yet. Add DNS record… gives an IP address a name." : "No DNS-only records yet."));
      else if (!shownDns.length) lanUi.dnsList.replaceChildren(empty("No DNS records match. Clear the filter."));
      else lanUi.dnsList.replaceChildren(...shownDns.map(lanDnsRow));
    });
    const published = new Set(routes.map(endpointKey));
    const open = lanEndpoints().filter((item) => !published.has(endpointKey(item)));
    lanUi.endpointCount.textContent = lanConfigured() ? String(open.length) : "";
    rerender(lanUi.endpoints, () => lanUi.endpoints.replaceChildren(!lanConfigured() ? empty("Nothing to show.")
      : !open.length ? empty("Every declared web endpoint already has a name.")
        : table(["Workload", "Endpoint", "Leads to", "Profile", ...(editable ? ["Action"] : [])], open.map((item) => {
          const key = endpointKey(item);
          const publish = button("Publish…", "secondary", `lan-publish:${key}`, () => openLanEditor("create", null, `lan-publish:${key}`, item));
          publish.setAttribute("aria-label", `Publish a LAN URL for ${workloadTitle(item.workload_id)}, endpoint ${text(item.endpoint_id)}`);
          publish.disabled = !canPlanLan("create") || Boolean(pending) || lan.busy;
          return [group("span", "", node("span", workloadTitle(item.workload_id)), node("span", text(item.workload_id), "row-sub machine")),
            node("span", text(item.endpoint_id), "machine"), node("span", lanTarget(item), "machine"), lanProfile(item), ...(editable ? [publish] : [])];
        }), "Declared web endpoints that no name leads to")));
    fillLanEndpoints();
    lanControls();
  }
  function lanRow(route) {
    const name = lanName(route);
    const pending = Boolean(lanPending());
    const summary = group("span", "record-summary",
      node("span", name, "record-name machine"),
      node("span", workloadTitle(route.workload_id), "record-state"),
      node("span", text(route.endpoint_id), "record-state machine"),
      lanProfile(route) !== "plain" ? node("span", `profile ${lanProfile(route)}`, "badge") : null,
      route.adopted === true ? node("span", "Adopted", "badge") : null);
    const body = node("div", undefined, "record-body");
    body.append(metadata([
      ["Open", lanLink(route, `lan-open:${name}`)],
      ["Workload", `${workloadTitle(route.workload_id)} (${text(route.workload_id)})`],
      ["Endpoint", node("span", text(route.endpoint_id), "machine")],
      ["Leads to", node("span", lanTarget(route), "machine")],
      ["Profile", lanProfile(route)],
      ...(route.adopted === true ? [["Origin", "Adopted from the gateway's existing configuration"]] : []),
    ]));
    if (canEditLan()) {
      const edit = button("Edit…", "secondary", `lan-edit:${name}`, () => openLanEditor("update", route, `lan-edit:${name}`));
      const remove = button("Remove…", "quiet", `lan-remove:${name}`, () => openLanEditor("delete", route, `lan-remove:${name}`));
      edit.setAttribute("aria-label", `Edit ${name}`);
      remove.setAttribute("aria-label", `Remove ${name}`);
      [edit, remove].forEach((item) => { item.disabled = !canPlanLan("update") || pending || lan.busy; });
      body.append(group("div", "body-actions", edit, remove));
      if (pending) body.append(node("p", "Finish or resume the unfinished change before editing or removing a name.", "field-note"));
    }
    return disclosure(`lan:${name}`, summary, body, "record lan-row");
  }
  function lanDnsRow(item) {
    const name = lanName(item);
    const registry = item.source === "registry";
    const address = text(item.address);
    const kind = address.includes(":") ? "AAAA" : "A";
    const summary = group("span", "record-summary",
      node("span", name, "record-name machine"), node("span", address, "record-state machine"),
      node("span", kind, "badge"), registry ? node("span", "Host registry · read-only", "badge") : node("span", "Manual", "record-state"));
    const body = node("div", undefined, "record-body");
    body.append(metadata([
      ["Name", node("span", name, "machine")],
      ["Address", node("span", address, "machine")],
      ["Type", kind],
      ["Source", registry ? "Generated from the host registry; edit the host to change it." : "Manual DNS record"],
      ...(item.host_id ? [["Host", group("span", "row-links", hostLink(item.host_id, `lan-dns:${name}`), node("span", item.host_id, "machine"))]] : []),
    ]));
    if (!registry && item.source === "manual" && canEditLan()) {
      const edit = button("Edit…", "secondary", `lan-dns-edit:${name}`, () => openLanEditor("dns-update", item, `lan-dns-edit:${name}`));
      const remove = button("Remove…", "quiet", `lan-dns-remove:${name}`, () => openLanEditor("dns-delete", item, `lan-dns-remove:${name}`));
      edit.setAttribute("aria-label", `Edit DNS record ${name}`);
      remove.setAttribute("aria-label", `Remove DNS record ${name}`);
      [edit, remove].forEach((control) => { control.disabled = !canPlanLan("dns-update") || Boolean(lanPending()) || lan.busy; });
      body.append(group("div", "body-actions", edit, remove));
      if (lanPending()) body.append(node("p", "Finish or resume the unfinished change before editing or removing a record.", "field-note"));
    }
    return disclosure(`lan-dns:${name}`, summary, body, "record lan-row");
  }
  // An unfinished change is a checkpoint, not a plan: it can be watched, or resumed through a new plan you approve.
  function lanPendingView(pending) {
    if (!pending) return [];
    const running = pending.status === "running";
    const stages = (value) => strings(value).join(", ") || "None";
    const renamed = pending.current_hostname && pending.hostname && pending.current_hostname !== pending.hostname;
    const parts = [node("h4", running ? "A change is being applied" : "A change stopped part way"),
      node("p", running
        ? "The names below stay as they are until the change is verified. This list reads again every few seconds while you watch."
        : "Some steps finished and others did not. New changes wait until this one is resumed. Resuming prepares a new plan for the remaining steps, which you review and approve.", "section-note"),
      metadata([
        ["Change", `${LAN_ACTIONS[pending.action] || sentence(text(pending.action))} ${text(pending.hostname, text(pending.current_hostname, ""))}`.trim()],
        ...(renamed ? [["Previous name", node("span", pending.current_hostname, "machine")]] : []),
        ["Status", group("span", "cell-state", lamp(running ? "transit" : "fail"), node("span", running ? "Running" : sentence(text(pending.status))))],
        ["Stage", text(pending.stage)],
        ["Done", stages(pending.completed)],
        ["Remaining", stages(pending.remaining)],
        ["Plan ID", node("span", text(pending.plan_id), "machine")],
        ["Started", timestamp(pending.started_at)],
        ["Last update", timestamp(pending.updated_at)],
        ["Receipts", strings(pending.receipts).join("\n") || "None yet"],
      ]),
      pending.error ? node("p", text(pending.error), "row-attention") : null];
    const actions = group("div", "body-actions",
      !running && canEditLan() ? button("Review and resume…", "primary", "lan-resume", () => openLanEditor("resume", null, "lan-resume")) : null,
      button("Show in the Audit log", "quiet", "lan-pending-audit", () => { selectTab("receipts", true); refreshReceipts(); }));
    if (!running && !canEditLan() && fleet?.read_only_view !== true) parts.push(node("p", "The operator can resume it here.", "field-note"));
    return [group("div", "blocker-box lan-pending", ...parts.filter(Boolean), actions)];
  }
  function fillLanEndpoints() {
    const select = lanUi.endpoint;
    const candidates = lanEndpoints();
    const current = lan.mode === "update" && lan.route && !candidates.some((item) => endpointKey(item) === endpointKey(lan.route)) ? lan.route : null;
    const groups = new Map();
    [...(current ? [current] : []), ...candidates].forEach((item) => {
      const id = text(item.workload_id, "");
      if (!groups.has(id)) groups.set(id, []);
      groups.get(id).push(item);
    });
    const entries = Array.from(groups, ([id, items]) => [`${workloadTitle(id)} (${id})`,
      items.map((item) => [endpointKey(item), `${lanEndpointLabel(item)}${item === current ? " (current; no longer offered)" : ""}`])]);
    // Rebuild only on a real change, so a cached update never closes the list under the operator's finger.
    const signature = JSON.stringify(entries);
    if (signature === lan.endpointSignature) return;
    lan.endpointSignature = signature;
    const keep = select.value;
    const placeholder = node("option", entries.length ? "Choose an endpoint" : "No endpoints are offered");
    placeholder.value = "";
    select.replaceChildren(placeholder, ...entries.map(([label, options]) => {
      const optgroup = node("optgroup");
      optgroup.label = label;
      optgroup.append(...options.map(([value, title]) => {
        const option = node("option", title);
        option.value = value;
        return option;
      }));
      return optgroup;
    }));
    select.value = Array.from(select.options).some((option) => option.value === keep) ? keep : "";
    if (keep && select.value !== keep && lan.mode && !lanUi.endpointField.hidden) {
      lanFieldError(select, lanUi.endpointError, "The endpoint you chose is no longer offered. Choose another.");
      lanDraftChanged();
    }
  }

  function openLanEditor(mode, route = null, from = null, endpoint = null) {
    if (!canPlanLan(mode) || lan.busy || (mode !== "resume" && lanPending())) return;
    Object.assign(lan, { mode, route, from, plan: null, planBody: null, planRevision: null, result: null, endpointSignature: "" });
    const name = lanName(route);
    const dns = lanDnsAction(mode);
    const editing = mode === "update" || mode === "dns-update";
    const naming = editing || mode === "create" || mode === "dns-create";
    lanUi.title.textContent = { create: "Publish LAN URL", update: `Edit ${name}`, delete: `Remove ${name}`,
      "dns-create": "Add DNS record", "dns-update": `Edit DNS record ${name}`, "dns-delete": `Remove DNS record ${name}`,
      resume: "Resume the unfinished change" }[mode];
    lanUi.note.textContent = {
      create: "Give a workload endpoint a name on the home network. The preview shows the DNS record and the gateway route this adds.",
      update: "Change the name, the endpoint it leads to, or both. The preview shows how the DNS record and the gateway route change.",
      delete: `Stop publishing ${name}. The preview shows the DNS record and the gateway route this removes. The workload itself is not touched.`,
      "dns-create": "Give an IPv4 or IPv6 address a name on the home network. This adds only a DNS record, not a gateway route or web URL.",
      "dns-update": "Change the DNS record's name, address or both. No gateway route or workload endpoint is changed.",
      "dns-delete": `Remove the DNS record for ${name}. This does not change a host, workload or gateway route.`,
      resume: "Plan the steps the unfinished change did not complete. The preview shows what remains to change.",
    }[mode];
    lanUi.hostnameField.hidden = !naming;
    lanUi.endpointField.hidden = !naming || dns;
    lanUi.addressField.hidden = !naming || !dns;
    lanUi.form.reset();
    const zones = lanZones();
    lanUi.hostname.value = editing ? name : "";
    lanUi.address.value = mode === "dns-update" ? text(route.address, "") : "";
    lanUi.hostname.placeholder = zones.length ? `name.${zones[0]}` : "";
    lanUi.hostnameNote.textContent = `The full name in lowercase${zones.length ? `, ending in ${zones.join(" or ")} like the names already published` : ", including its zone"}. The desk checks it is in a zone it serves.`;
    fillLanEndpoints();
    lanUi.endpoint.value = mode === "update" ? endpointKey(route) : endpoint ? endpointKey(endpoint) : "";
    lanUi.submit.textContent = mode === "resume" ? "Prepare resume plan" : mode === "delete" || mode === "dns-delete" ? "Preview removal" : "Preview changes";
    lanFieldError(lanUi.hostname, lanUi.hostnameError, "");
    lanFieldError(lanUi.endpoint, lanUi.endpointError, "");
    lanFieldError(lanUi.address, lanUi.addressError, "");
    clearLanPlan();
    lanUi.result.replaceChildren();
    lanUi.formStatus.textContent = "";
    error(lanUi.formError, "");
    lanUi.editor.hidden = false;
    lanControls();
    lanUi.editor.scrollIntoView({ block: "nearest" });
    (naming ? lanUi.hostname : lanUi.title).focus({ preventScroll: true });
  }
  function closeLanEditor() {
    if (lan.busy) return;
    const from = lan.from;
    Object.assign(lan, { mode: null, route: null, from: null, plan: null, planBody: null, planRevision: null, result: null });
    lanUi.form.reset();
    clearLanPlan();
    lanUi.result.replaceChildren();
    lanUi.formStatus.textContent = "";
    error(lanUi.formError, "");
    lanUi.editor.hidden = true;
    const target = from && Array.from(byId("panel-lan-urls").querySelectorAll("[data-focus-key]")).find((item) => item.dataset.focusKey === from);
    (target && !target.disabled && !target.hidden ? target : byId("lan-urls-title")).focus();
  }
  function clearLanPlan() {
    Object.assign(lan, { plan: null, planBody: null, planRevision: null });
    lanUi.plan.replaceChildren();
    lanUi.approve.checked = false;
    lanControls();
  }
  function lanDraftChanged() {
    if (!lan.plan && !lan.result) return;
    lan.result = null;
    clearLanPlan();
    lanUi.result.replaceChildren();
    lanUi.formStatus.textContent = "Draft changed. Preview again before applying.";
  }
  // Checks what the page can know; the server decides zones, IP addresses, endpoints and conflicts again.
  function lanRequest() {
    const mode = lan.mode;
    const body = { action: mode, expected_revision: lan.data?.revision };
    if (mode === "delete" || mode === "dns-delete") body.current_hostname = lan.route.hostname;
    const dns = lanDnsAction(mode);
    const editing = mode === "update" || mode === "dns-update";
    if (!editing && mode !== "create" && mode !== "dns-create") return { body };
    const hostname = lanUi.hostname.value.trim().toLowerCase();
    if (hostname !== lanUi.hostname.value) lanUi.hostname.value = hostname;
    const current = editing ? lan.route.hostname : null;
    const zones = lanZones();
    const nameProblem = !hostname ? `Enter the full name${zones.length ? `, such as name.${zones[0]}` : ""}.`
      : hostname.endsWith(".") ? "Leave off the final dot."
        : !LAN_HOSTNAME.test(hostname) ? "Use a full name: dot-separated parts of lowercase letters, digits and hyphens, each at most 63 characters and not starting or ending with a hyphen."
          : hostname !== current && [...lanRoutes(), ...lanDnsRecords()].some((item) => item.hostname === hostname) ? "That name is already in use. Edit its existing entry or choose another name." : "";
    lanFieldError(lanUi.hostname, lanUi.hostnameError, nameProblem);
    if (dns) {
      const address = lanUi.address.value.trim();
      lanUi.address.value = address;
      const addressProblem = address ? "" : "Enter an IPv4 or IPv6 address.";
      lanFieldError(lanUi.address, lanUi.addressError, addressProblem);
      if (nameProblem || addressProblem) return { invalid: nameProblem ? lanUi.hostname : lanUi.address };
      if (current && hostname === current && address === lan.route.address) return { problem: "Nothing changed. Change the name, address or both." };
      Object.assign(body, { hostname, address }, current ? { current_hostname: current } : {});
      return { body };
    }
    const chosen = lanUi.endpoint.value;
    const endpointProblem = chosen ? "" : "Choose the workload endpoint this name leads to.";
    lanFieldError(lanUi.endpoint, lanUi.endpointError, endpointProblem);
    if (nameProblem || endpointProblem) return { invalid: nameProblem ? lanUi.hostname : lanUi.endpoint };
    if (current && hostname === current && chosen === endpointKey(lan.route)) return { problem: "Nothing changed. Change the name, the endpoint or both." };
    const [workloadId, endpointId] = JSON.parse(chosen);
    Object.assign(body, { hostname, workload_id: workloadId, endpoint_id: endpointId }, current ? { current_hostname: current } : {});
    return { body };
  }
  async function planLan(event) {
    event.preventDefault();
    if (lan.busy || !lan.mode || lanUi.submit.disabled) return;
    error(lanUi.formError, "");
    const request = lanRequest();
    if (request.invalid) { request.invalid.focus(); return; }
    if (request.problem) { error(lanUi.formError, request.problem); return; }
    lan.result = null;
    lanUi.result.replaceChildren();
    clearLanPlan();
    lan.busy = true;
    lanControls();
    lanUi.formStatus.textContent = "Preparing the plan. Nothing changes until you approve and apply it.";
    try {
      const plan = await api("/api/lan-urls/plan", request.body);
      if (typeof plan.id !== "string" || !plan.id) throw new Error("The plan response did not match the expected shape.");
      Object.assign(lan, { plan, planBody: request.body, planRevision: request.body.expected_revision });
      lanUi.requestId.value = crypto.randomUUID();
      lanUi.formStatus.textContent = lanApplicable(plan) ? "Plan ready. Review every change below, then approve it." : "This plan cannot be applied. The reasons are below.";
    } catch (cause) {
      lanUi.formStatus.textContent = "";
      error(lanUi.formError, cause.message);
      // A refused revision means the registry moved on: read it again so the next preview uses it.
      if (cause.status === 409) loadLanUrls();
    } finally {
      lan.busy = false;
      renderLanPlan();
      lanControls();
      if (lan.plan) byId("lan-url-plan-title")?.focus();
    }
  }
  function lanChange(change, index) {
    const target = text(change.target, `change ${index + 1}`);
    const pre = node("pre", undefined, "evidence diff");
    pre.tabIndex = 0;
    pre.setAttribute("aria-label", `Changes to ${target}`);
    const lines = typeof change.diff === "string" ? change.diff.replace(/\n$/, "").split("\n") : JSON.stringify(change.diff ?? null, null, 2).split("\n");
    pre.append(...lines.map((line) => node("span", line, line.startsWith("+++") || line.startsWith("---") ? "diff-file"
      : line.startsWith("+") ? "diff-add" : line.startsWith("-") ? "diff-del" : line.startsWith("@@") ? "diff-hunk" : undefined)));
    return group("div", "lan-change", node("h5", `Changes to ${target}`), pre);
  }
  function lanSteps(steps) {
    return array(steps).map((step) => typeof step === "string" ? step
      : record(step) ? text(step.description, text(step.title, text(step.summary, JSON.stringify(step)))) : String(step));
  }
  function renderLanPlan() {
    const plan = lan.plan;
    if (!plan) { lanUi.plan.replaceChildren(); return; }
    const request = lan.planBody || {};
    const blockers = strings(plan.blockers);
    const warnings = strings(plan.warnings);
    const changes = array(plan.changes).filter(record);
    const title = node("h4", `Plan: ${LAN_ACTIONS[plan.action] || LAN_ACTIONS[request.action] || sentence(text(plan.action))}`);
    title.id = "lan-url-plan-title";
    title.tabIndex = -1;
    const endpoint = request.workload_id ? lanEndpoints().find((item) => endpointKey(item) === endpointKey(request))
      || (lan.route && endpointKey(lan.route) === endpointKey(request) ? lan.route : null) : null;
    lanUi.plan.replaceChildren(...[title, metadata([
      ...(request.hostname || request.current_hostname ? [["Name", node("span", text(request.hostname, request.current_hostname), "machine")]] : []),
      ...(request.hostname && request.current_hostname && request.hostname !== request.current_hostname ? [["Previous name", node("span", request.current_hostname, "machine")]] : []),
      ...(request.address ? [["Address", node("span", request.address, "machine")], ["Type", request.address.includes(":") ? "AAAA" : "A"]] : []),
      ...(request.workload_id ? [["Leads to", `${workloadTitle(request.workload_id)}, ${endpoint ? lanEndpointLabel(endpoint) : text(request.endpoint_id)}`]] : []),
      ["Plan ID", node("span", text(plan.id), "machine")],
      ["Expires", timestamp(plan.expires_at)],
    ]),
    blockers.length ? group("div", "blocker-box", node("h4", "Cannot be applied"), list(blockers, "")) : null,
    warnings.length ? group("div", "blocker-box", node("h4", "Warnings"), list(warnings, "")) : null,
    node("h4", changes.length === 1 ? "1 change" : `${changes.length} changes`),
    ...(changes.length ? changes.map(lanChange) : [empty("This plan changes nothing.")]),
    node("h4", "Steps"), list(lanSteps(plan.steps), "No steps listed.")].filter(Boolean));
  }
  function lanControls() {
    const plan = lan.plan;
    const expiry = Date.parse(plan?.expires_at);
    const expired = Boolean(plan) && Number.isFinite(expiry) && expiry <= Date.now();
    const moved = Boolean(plan) && !lan.applying && lan.data?.revision !== lan.planRevision;
    const running = lanPending()?.status === "running";
    const blockedByPending = Boolean(lanPending()) && (lan.mode !== "resume" || running);
    const ready = lanApplicable(plan) && !expired && !moved && !lan.result && canPlanLan(lan.mode) && !blockedByPending;
    lanUi.form.hidden = Boolean(lan.result);
    lanUi.submit.disabled = lan.busy || !lan.mode || !canPlanLan(lan.mode) || blockedByPending;
    lanUi.hostname.disabled = lan.busy;
    lanUi.endpoint.disabled = lan.busy;
    lanUi.address.disabled = lan.busy;
    lanUi.close.disabled = lan.busy;
    lanUi.approval.hidden = !lanApplicable(plan) || Boolean(lan.result);
    lanUi.approve.disabled = !ready || lan.busy;
    lanUi.requestId.disabled = !ready || lan.busy;
    lanUi.apply.disabled = !ready || lan.busy || !lanUi.approve.checked || !lanUi.requestId.value.trim();
    lanUi.apply.textContent = lan.applying ? "Applying…" : "Apply approved plan";
    const count = array(plan?.changes).length;
    const name = lan.planBody?.hostname || lan.planBody?.current_hostname;
    lanUi.approveText.textContent = `I approve applying exactly ${count === 1 ? "this change" : `these ${count} changes`}${name ? ` for ${name}` : ""}.`;
    const note = !plan || lan.result || lan.applying ? "" : expired ? "This plan expired. Preview again to apply."
      : moved ? "LAN URLs or DNS records changed since this plan was prepared. Preview again."
        : blockedByPending ? (running ? "A change is being applied; it is shown above the list. Wait for it to finish." : "An unfinished change blocks this plan. Resume it first.")
        : !canEditLan() ? "Applying needs the operator's session."
          : !canPlanLan(lan.mode) ? "This change is unavailable. Reload to read its current availability." : "";
    lanUi.approvalNote.textContent = note;
    lanUi.approvalNote.hidden = !note;
  }
  async function applyLan() {
    const plan = lan.plan;
    if (!plan || lan.busy || lanUi.apply.disabled || !lanUi.approve.checked) return;
    const body = { plan_id: plan.id, approved: true, request_id: lanUi.requestId.value.trim() };
    Object.assign(lan, { busy: true, applying: true });
    error(lanUi.formError, "");
    renderLanUrls();
    lanUi.formStatus.textContent = "Applying. Each host's change runs under its lease and the names are checked afterwards, which can take several minutes. Keep this page open to see the result.";
    scheduleLanPoll();
    try {
      const result = await api("/api/lan-urls/apply", body, LAN_APPLY_MS);
      if (!["succeeded", "partial"].includes(result.status)) throw new Error("The apply response did not match the expected shape. Reload LAN URLs and read the Audit log before anything else.");
      lan.result = { ...result, request_id: body.request_id };
      if (lan.data) {
        lan.data = { ...lan.data, ...(result.revision !== undefined ? { revision: result.revision } : {}),
          ...(Array.isArray(result.routes) ? { routes: result.routes.filter(record) } : {}),
          ...(Array.isArray(result.dns_records) ? { dns_records: result.dns_records.filter(record) } : {}),
          pending: record(result.pending) ? result.pending : null };
      }
      lanUi.formStatus.textContent = result.status === "succeeded" ? "Applied." : "Applied part way. The unfinished change is shown above the list; resume it when ready.";
      refreshReceipts();
    } catch (cause) {
      error(lanUi.formError, cause.message);
      lanUi.formStatus.textContent = number(cause.status) && cause.status < 500 ? "The desk refused the apply."
        : "The outcome is not known. Reload LAN URLs before anything else: an unfinished change shows above the list. Applying again with the same request ID returns the first result instead of running twice.";
    } finally {
      Object.assign(lan, { busy: false, applying: false });
      renderLanResult();
      renderLanUrls();
      loadLanUrls();
      if (lan.result) byId("lan-url-result-title")?.focus();
    }
  }
  function renderLanResult() {
    const result = lan.result;
    if (!result) { lanUi.result.replaceChildren(); return; }
    const ok = result.status === "succeeded";
    const title = node("h4", ok ? "Applied" : "Applied part way");
    title.id = "lan-url-result-title";
    title.tabIndex = -1;
    const name = lan.planBody?.hostname;
    const dns = lanDnsAction(lan.planBody?.action) || lan.plan?.gateway === null;
    const route = ok && name && !dns ? array(result.routes).filter(record).find((item) => item.hostname === name) : null;
    lanUi.result.replaceChildren(...[title, metadata([
      ["Outcome", group("span", "cell-state", lamp(ok ? "run" : "fail"), node("span", ok ? "Succeeded" : "Partial: some steps did not finish"))],
      ...(dns && (name || lan.planBody?.current_hostname) ? [["Name", node("span", name || lan.planBody.current_hostname, "machine")]] : []),
      ...(dns && lan.planBody?.address ? [["Address", node("span", lan.planBody.address, "machine")]] : []),
      ...(route ? [["Open", lanLink(route, "lan-result-open")]] : []),
      ["Request ID", node("span", text(result.request_id), "machine")],
      ["Receipts", strings(result.receipts).join("\n") || "None"],
    ]), result.error ? node("p", text(result.error), "row-attention") : null,
    group("div", "body-actions",
      !ok && canEditLan() ? button("Review and resume…", "primary", "lan-result-resume", () => openLanEditor("resume", null, "lan-resume")) : null,
      button("Show in the Audit log", "quiet", null, () => { selectTab("receipts", true); refreshReceipts(); }))].filter(Boolean));
  }

  // --- Views ---
  const TAB_TITLES = { workloads: "Workloads", "lan-urls": "LAN URLs", hosts: "Hosts", agents: "Agents", playbooks: "Playbooks", access: "Access", migration: "Cold migration", receipts: "Audit log" };
  let currentTab = "workloads";
  function selectTab(name, focus = false) {
    tabs.forEach((tab) => {
      const active = tab === name;
      byId(`tab-${tab}`).setAttribute("aria-selected", String(active));
      byId(`tab-${tab}`).tabIndex = active ? 0 : -1;
      byId(`panel-${tab}`).hidden = !active;
    });
    currentTab = name;
    document.title = `${TAB_TITLES[name]} - Switchyard`;
    // `#access/<id>` (the link an enrolling client prints) stays in the address while its tab is open.
    const hash = window.location.hash;
    if (hash !== `#${name}` && !hash.startsWith(`#${name}/`)) window.history.replaceState(null, "", `#${name}`);
    if (name !== "access") { access.target = null; access.located = null; }
    // Keep the chosen tab visible on a narrow screen without moving the page itself.
    const tab = byId(`tab-${name}`);
    const strip = tab.parentElement;
    strip.scrollLeft += tab.getBoundingClientRect().left - strip.getBoundingClientRect().left - (strip.clientWidth - tab.offsetWidth) / 2;
    if (focus) byId(`tab-${name}`).focus();
    if (name === "access") loadAccess(); else scheduleAccessPoll();
    // Before the first fleet read the session is not known yet; the first read loads this tab.
    if (name === "playbooks" && fleet) loadPlaybooks(); else schedulePlaybookPoll();
    // LAN URLs are read each time their tab is shown, never before.
    if (name === "lan-urls" && fleet) loadLanUrls(); else scheduleLanPoll();
  }
  // "/" jumps to the current view's filter, as in most consoles and code hosts.
  document.addEventListener("keydown", (event) => {
    const active = document.activeElement;
    if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(active?.tagName || "")) return;
    const field = { workloads: ui.definedSearch, "lan-urls": lanUi.search, hosts: ui.hostSearch }[currentTab];
    if (!field) return;
    event.preventDefault();
    field.focus();
    field.select();
  });
  tabs.forEach((name) => {
    const tab = byId(`tab-${name}`);
    tab.addEventListener("click", () => selectTab(name));
    tab.addEventListener("keydown", (event) => {
      const shown = tabs.filter((item) => !byId(`tab-${item}`).hidden);
      const index = shown.indexOf(name);
      let target;
      if (event.key === "ArrowRight") target = (index + 1) % shown.length;
      if (event.key === "ArrowLeft") target = (index + shown.length - 1) % shown.length;
      if (event.key === "Home") target = 0;
      if (event.key === "End") target = shown.length - 1;
      if (target !== undefined) { event.preventDefault(); selectTab(shown[target], true); }
    });
  });
  const fromHash = () => {
    const [name, ...rest] = window.location.hash.slice(1).split("/");
    if (!tabs.includes(name) || byId(`tab-${name}`).hidden) return;
    if (name === "access") {
      let id = null;
      try { id = rest.length ? decodeURIComponent(rest.join("/")) : null; } catch (cause) { id = rest.join("/"); }
      if (id !== access.target) { access.target = id || null; access.located = null; access.signature = ""; }
    }
    if (name === "playbooks" && rest.length) {
      try { pb.pendingRun = decodeURIComponent(rest.join("/")); } catch (cause) { pb.pendingRun = null; }
    }
    selectTab(name);
  };
  window.addEventListener("hashchange", fromHash);
  fromHash();
  signInUi.form.addEventListener("submit", signIn);
  signInUi.cancel.addEventListener("click", () => {
    hideSignIn();
    (signInReturn?.isConnected ? signInReturn : byId("session-action")).focus();
  });
  byId("session-action").addEventListener("click", (event) => {
    if (isOperator()) signOut();
    else { signInReturn = event.currentTarget; showSignIn(); }
  });
  accessUi.refresh.addEventListener("click", () => loadAccess(true));
  pbUi.refresh.addEventListener("click", () => loadPlaybooks(true));
  pbUi.add.addEventListener("click", () => openEditor("add"));
  lanUi.publish.dataset.focusKey = "lan-publish";
  lanUi.publish.addEventListener("click", () => openLanEditor("create", null, "lan-publish"));
  lanUi.addDns.dataset.focusKey = "lan-add-dns";
  lanUi.addDns.addEventListener("click", () => openLanEditor("dns-create", null, "lan-add-dns"));
  lanUi.refresh.addEventListener("click", () => loadLanUrls(true));
  lanUi.search.addEventListener("input", renderLanUrls);
  lanUi.close.addEventListener("click", closeLanEditor);
  lanUi.form.addEventListener("submit", planLan);
  lanUi.hostname.addEventListener("input", () => { lanFieldError(lanUi.hostname, lanUi.hostnameError, ""); lanDraftChanged(); });
  lanUi.endpoint.addEventListener("change", () => { lanFieldError(lanUi.endpoint, lanUi.endpointError, ""); lanDraftChanged(); });
  lanUi.address.addEventListener("input", () => { lanFieldError(lanUi.address, lanUi.addressError, ""); lanDraftChanged(); });
  lanUi.approve.addEventListener("change", lanControls);
  lanUi.requestId.addEventListener("input", lanControls);
  lanUi.apply.addEventListener("click", applyLan);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopAccessPoll();
    else if (currentTab === "access" || pendingRequests().length) loadAccess();
    schedulePlaybookPoll();
    scheduleLanPoll();
  });
  ui.reload.addEventListener("click", () => loadFleet(true));
  byId("refresh-agents").addEventListener("click", loadAgents);
  paseoEditor.form.addEventListener("submit", reviewPaseo);
  [paseoEditor.listen, paseoEditor.cli].forEach((field) => field.addEventListener("input", () => {
    paseoReviewed = null;
    paseoEditor.review.replaceChildren();
    paseoEditor.status.textContent = "Draft changed. Review current configuration before saving.";
    paseoEditorControls();
  }));
  paseoEditor.save.addEventListener("click", savePaseo);
  byId("close-paseo-editor").addEventListener("click", () => {
    if (paseoPending) return;
    paseoDraft = null;
    paseoReviewed = null;
    paseoEditor.form.reset();
    paseoEditor.review.replaceChildren();
    paseoEditor.panel.hidden = true;
    paseoEditorControls();
  });
  byId("monitor-chip").addEventListener("click", () => {
    selectTab("hosts");
    const details = byId("monitoring-details");
    details.open = true;
    details.scrollIntoView({ block: "nearest" });
    details.firstElementChild.focus({ preventScroll: true });
  });
  ui.hostSearch.addEventListener("input", renderHosts);
  ui.definedSearch.addEventListener("input", renderWorkloads);
  byId("defined-state").addEventListener("change", renderWorkloads);
  byId("host-filter").addEventListener("click", () => {
    workloadHostFilter = null;
    renderWorkloads();
    ui.definedSearch.focus({ preventScroll: true });
  });
  ui.workloadSearch.addEventListener("input", () => { renderDiscovery(); renderArtifacts(); });
  ui.lifecycle.addEventListener("change", renderDiscovery);
  [ui.freshness, ui.backend, ui.scope].forEach((select) => select.addEventListener("change", () => { renderDiscovery(); renderArtifacts(); }));
  ui.grouping.addEventListener("change", renderDiscovery);
  ui.workload.addEventListener("change", () => { clearProposal(); fillSelections(); renderContexts(); updateControls(); });
  ui.target.addEventListener("change", () => { clearProposal(); renderContexts(); updateControls(); });
  ui.form.addEventListener("submit", prepareProposal);
  byId("next-destination").addEventListener("click", () => showStep(2));
  byId("next-review").addEventListener("click", () => showStep(3));
  for (let step = 1; step <= 3; step += 1) byId(`step-${step}`).addEventListener("click", () => showStep(step));
  document.querySelectorAll("[data-back]").forEach((button) => button.addEventListener("click", () => showStep(Number(button.dataset.back))));
  op.form.addEventListener("submit", prepareOperation);
  op.inspect.addEventListener("click", inspectManagedWorkload);
  byId("open-workload-operations").addEventListener("click", () => {
    const workload = array(operationPolicy().workloads).find((item) => item.id === ui.workload.value && strings(item.actions).includes("migrate"))
      || array(operationPolicy().workloads).find((item) => strings(item.actions).includes("migrate"));
    if (workload) openOperation(workload.id, "migrate");
  });
  byId("close-operations").addEventListener("click", () => {
    const id = op.workload.value;
    operationsOpen = false;
    sideDesk();
    renderWorkloads();
    Array.from(ui.workloads.querySelectorAll("[data-focus-key]")).find((item) => item.dataset.focusKey === `manage:${id}`)?.focus();
  });
  op.workload.addEventListener("change", () => { fillOperationChoices(); clearOperationPlan(); renderWorkloads(); });
  [op.action, op.target].forEach((select) => select.addEventListener("change", clearOperationPlan));
  op.approval.addEventListener("change", operationControls);
  op.requestId.addEventListener("input", operationControls);
  op.execute.addEventListener("click", executeOperation);
  op.shellForm.addEventListener("submit", runShell);
  op.shellHost.addEventListener("change", operationControls);
  byId("shell-new-request").addEventListener("click", () => { op.shellId.value = crypto.randomUUID(); });
  byId("refresh-operations").addEventListener("click", refreshReceipts);
  byId("receipt-filter").addEventListener("change", () => renderReceipts(array(fleet?.operations)));
  byId("fleet-keys-form").addEventListener("submit", prepareFleetKeys);
  byId("inspect-fleet-keys").addEventListener("click", inspectFleetKeys);
  byId("execute-fleet-keys").addEventListener("click", executeFleetKeys);
  [keys.hosts, keys.action].forEach((field) => field.addEventListener("change", clearKeyPlan));
  keys.approval.addEventListener("change", keyControls);
  keys.requestId.addEventListener("input", keyControls);
  editor.form.addEventListener("submit", reviewDefinition);
  [editor.id, editor.name, editor.purpose].forEach((field) => field.addEventListener("input", invalidateDefinitionReview));
  editor.supporting.addEventListener("change", invalidateDefinitionReview);
  editor.save.addEventListener("click", saveDefinition);
  byId("cancel-definition").addEventListener("click", () => {
    if (definitionPending) return;
    definitionDraft = null;
    definitionReviewed = null;
    editor.panel.hidden = true;
    sideDesk();
    editor.form.reset();
    editor.review.replaceChildren();
    editor.status.textContent = "";
    error(editor.error, "");
    definitionControls();
  });
  hostEditor.form.addEventListener("submit", reviewHost);
  Object.values(hostFields).forEach((field) => field.addEventListener("input", () => {
    hostReviewed = null;
    hostEditor.review.replaceChildren();
    clearHostScan();
    hostEditor.status.textContent = "Draft changed. Review current hosts before saving.";
    hostEditorControls();
  }));
  hostEditor.save.addEventListener("click", saveHost);
  byId("scan-host-key").addEventListener("click", scanHostKey);
  hostEditor.confirm.addEventListener("change", hostEditorControls);
  byId("pin-host-key").addEventListener("click", pinHostKey);
  byId("close-host-editor").addEventListener("click", () => {
    if (hostPending) return;
    const id = hostDraft?.original.id;
    hostDraft = null;
    hostReviewed = null;
    clearHostScan();
    hostEditor.form.reset();
    hostEditor.panel.hidden = true;
    Array.from(ui.hosts.querySelectorAll("[data-focus-key]")).find((item) => item.dataset.focusKey === `edit-host:${id}`)?.focus();
  });
  // Local labels only. This interval never fetches or collects.
  window.setInterval(() => {
    document.querySelectorAll(".freshness").forEach(updateAge);
    document.querySelectorAll(".countdown").forEach(updateCountdown);
    operationControls();
    keyControls();
    hostEditorControls();
    if (!lanUi.editor.hidden) lanControls();
    document.querySelectorAll("[data-observe-host]").forEach((button) => {
      const host = fleet?.hosts.find((item) => item.id === button.dataset.observeHost);
      if (host) updateObserveButton(button, host);
    });
  }, 1000);
  window.addEventListener("pagehide", () => { pageClosed = true; pauseStream(); stopAccessPoll(); window.clearTimeout(pb.timer); pb.timer = null; window.clearTimeout(lan.timer); lan.timer = null; });
  // Only a page restored from the back-forward cache needs restarting; a fresh load starts in boot().
  window.addEventListener("pageshow", (event) => { if (!event.persisted) return; pageClosed = false; startStream(); scheduleAccessPoll(); schedulePlaybookPoll(); scheduleLanPoll(); });
  boot();
})();
