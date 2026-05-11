const API_BASE = "http://127.0.0.1:8000";

const fileInput = document.getElementById("fileInput");
const fileLabel = document.getElementById("fileLabel");
const analyzeBtn = document.getElementById("analyzeBtn");
const uploadCard = document.getElementById("uploadCard");
const resultsBody = document.getElementById("resultsBody");
const resultsTitle = document.getElementById("resultsTitle");
const newInvBtn = document.getElementById("newInvBtn");
const newInvFileInput = document.getElementById("newInvFileInput");
const prevLogsList = document.getElementById("prevLogsList");

const PLACEHOLDER_TEXT = "data.pcap";
const TITLE_PRE_RESULTS = "file viewBox";
const TITLE_RESULTS = "results";
const LAST_ANALYSIS_KEY = "swellscan.lastAnalysis";

function rememberLastAnalysis(analysisId, filename) {
  try {
    sessionStorage.setItem(
      LAST_ANALYSIS_KEY,
      JSON.stringify({ id: analysisId, filename: filename || "" }),
    );
  } catch {}
}

async function restoreLastAnalysis() {
  let saved = null;
  try {
    const raw = sessionStorage.getItem(LAST_ANALYSIS_KEY);
    if (raw) saved = JSON.parse(raw);
  } catch {
    saved = null;
  }
  if (!saved || saved.id == null) return;
  try {
    const gen = claimResults();
    const analysis = await fetchAnalysisFromDb(saved.id);
    if (gen !== resultsGeneration) return;
    activeLogId = analysis.log_id ?? null;
    renderAnalysisFromDb(analysis, saved.filename || "");
    setResultsTitle(TITLE_RESULTS);
    hasRenderedAnalysis = true;
  } catch (err) {
    console.warn("Could not restore last analysis:", err);
  }
}

function setResultsTitle(text) {
  if (resultsTitle) resultsTitle.textContent = text;
}

let currentUser = null;
let activeLogId = null;
let resultsGeneration = 0;
let hasRenderedAnalysis = false;

function claimResults() {
  return ++resultsGeneration;
}

function setFileLabel(name) {
  fileLabel.textContent = name || PLACEHOLDER_TEXT;
  fileLabel.classList.toggle("has-file", Boolean(name));
}

function syncFileToMain(file) {
  const dt = new DataTransfer();
  dt.items.add(file);
  fileInput.files = dt.files;
  setFileLabel(file.name);
}

function startNewInvestigation() {
  fileInput.value = "";
  setFileLabel(null);
  if (newInvFileInput) {
    newInvFileInput.value = "";
    newInvFileInput.click();
  }
}

function resetResultsPlaceholder() {
  if (hasRenderedAnalysis) return;
  claimResults();
  setResultsTitle(TITLE_PRE_RESULTS);
  resultsBody.innerHTML = `
    <p>
      Text about the data you get and steps: upload a CSV of network features, then
      <strong>Analyze</strong> sends it to the API. Results show row-level probabilities and labels.
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
      IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM IPSUMIOREM
    </p>
  `;
}

fileLabel.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  const f = fileInput.files[0];
  setFileLabel(f ? f.name : null);
  if (f) previewLocalCsv(f);
});

newInvBtn.addEventListener("click", () => {
  startNewInvestigation();
});

newInvFileInput.addEventListener("change", async () => {
  const f = newInvFileInput.files[0];
  if (!f) return;
  syncFileToMain(f);
  const lower = f.name.toLowerCase();
  if (!lower.endsWith(".csv")) {
    resultsBody.innerHTML =
      '<p class="error">The backend currently accepts <strong>.csv</strong> only. Choose a CSV to analyze.</p>';
    newInvFileInput.value = "";
    return;
  }
  await analyze(f);
  newInvFileInput.value = "";
});

["dragenter", "dragover"].forEach((ev) => {
  uploadCard.addEventListener(ev, (e) => {
    e.preventDefault();
    uploadCard.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((ev) => {
  uploadCard.addEventListener(ev, (e) => {
    e.preventDefault();
    uploadCard.classList.remove("dragover");
  });
});

uploadCard.addEventListener("drop", (e) => {
  const f = e.dataTransfer?.files?.[0];
  if (!f) return;
  const lower = f.name.toLowerCase();
  if (!lower.endsWith(".csv") && !lower.endsWith(".pcap")) {
    alert("Please drop a .csv or .pcap file.");
    return;
  }
  const dt = new DataTransfer();
  dt.items.add(f);
  fileInput.files = dt.files;
  setFileLabel(f.name);
  previewLocalCsv(f);
});

async function analyze(fileOverride = null) {
  const file = fileOverride ?? fileInput.files[0];
  if (!file) {
    alert("Please choose a file first (click the field or drop a file).");
    return;
  }
  claimResults();
  const lower = file.name.toLowerCase();
  if (!lower.endsWith(".csv")) {
    resultsBody.innerHTML =
      '<p class="error">The backend currently accepts <strong>.csv</strong> only. Choose a CSV to analyze.</p>';
    return;
  }

  analyzeBtn.disabled = true;
  resultsBody.innerHTML = "<p>Analyzing…</p>";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const uploadResp = await fetch(`${API_BASE}/upload-csv`, {
      method: "POST",
      body: formData,
    });
    const uploadJson = await uploadResp.json().catch(() => ({}));
    if (!uploadResp.ok) {
      const detail =
        typeof uploadJson.detail === "string"
          ? uploadJson.detail
          : JSON.stringify(uploadJson.detail || uploadJson);
      resultsBody.innerHTML = `<p class="error">Upload failed (${uploadResp.status})</p><pre class="json">${escapeHtml(detail)}</pre>`;
      return;
    }

    const analysisId = uploadJson.analysis_id;
    if (analysisId == null) {
      resultsBody.innerHTML = `<p class="error">Upload succeeded but the server did not return an analysis id.</p><pre class="json">${escapeHtml(JSON.stringify(uploadJson, null, 2))}</pre>`;
      return;
    }

    resultsBody.innerHTML = "<p>Fetching analysis from database…</p>";
    const analysis = await fetchAnalysisFromDb(analysisId);
    activeLogId = analysis.log_id ?? null;
    renderAnalysisFromDb(analysis, file.name);
    setResultsTitle(TITLE_RESULTS);
    hasRenderedAnalysis = true;
    rememberLastAnalysis(analysis.id, file.name);
    refreshPreviousLogs();
  } catch (err) {
    resultsBody.innerHTML = `<p class="error">Network error — is the API running at ${API_BASE}?</p><pre class="json">${escapeHtml(String(err))}</pre>`;
  } finally {
    analyzeBtn.disabled = false;
  }
}

async function fetchAnalysisFromDb(analysisId) {
  const resp = await fetch(`${API_BASE}/analyses/${encodeURIComponent(analysisId)}`);
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const detail =
      typeof json.detail === "string" ? json.detail : JSON.stringify(json.detail || json);
    throw new Error(`GET /analyses/${analysisId} failed (${resp.status}): ${detail}`);
  }
  return json;
}

function renderAnalysisFromDb(analysis, fallbackName = "") {
  const log = analysis.log || {};
  const inference = analysis.analysis_data || {};
  const result = (analysis.results && analysis.results[0]) || {};

  const filename = log.filename || fallbackName || "(unknown file)";
  const rows = inference.rows ?? log.rows ?? "—";
  const malwareCount = result.malware_quantity ?? inference.malware_count ?? "—";
  const malwareLocations = Array.isArray(result.malware_location)
    ? result.malware_location
    : [];
  const connectionNumbers = malwareLocations.map((i) => i + 1);
  const classified = result.analysis_classification ? "Malware detected" : "Clean";

  resultsBody.innerHTML = `
    <p>
      Analysis <strong>#${escapeHtml(String(analysis.id))}</strong> for
      <strong>${escapeHtml(filename)}</strong>
      ${analysis.created_at ? `(<em>${escapeHtml(analysis.created_at)}</em>)` : ""}
      — sourced from the database.
    </p>
    <div class="stats">
      <div><strong>Verdict</strong>: ${escapeHtml(classified)}</div>
      <div><strong>Rows</strong>: ${escapeHtml(String(rows))}</div>
      <div><strong>Malware count</strong>: ${escapeHtml(String(malwareCount))}</div>
      <div><strong>Connection number</strong>: ${escapeHtml(
        connectionNumbers.length ? connectionNumbers.join(", ") : "—",
      )}</div>
      ${renderMaliciousRecords(analysis.malicious_records)}
    </div>
    <p><strong>CSV preview</strong> (first ${escapeHtml(
      String(Array.isArray(analysis.sample) ? analysis.sample.length : 0),
    )} rows from the database):</p>
    ${renderSampleTable(analysis.sample)}
  `;
}

function renderSampleTable(sample) {
  if (!Array.isArray(sample) || sample.length === 0) {
    return '<p class="sample-empty">No CSV preview stored for this analysis.</p>';
  }

  const columnOrder = [];
  const seen = new Set();
  for (const entry of sample) {
    const row = entry.row_data || {};
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) {
        seen.add(key);
        columnOrder.push(key);
      }
    }
  }

  const head = `
    <tr>
      <th>#</th>
      ${columnOrder.map((c) => `<th>${escapeHtml(c)}</th>`).join("")}
    </tr>
  `;

  const body = sample
    .map((entry) => {
      const row = entry.row_data || {};
      const cells = columnOrder
        .map((c) => {
          const value = row[c];
          const text =
            value == null
              ? ""
              : typeof value === "object"
                ? JSON.stringify(value)
                : String(value);
          return `<td>${escapeHtml(text)}</td>`;
        })
        .join("");
      return `<tr><td class="row-num">${escapeHtml(String(entry.row_index + 1))}</td>${cells}</tr>`;
    })
    .join("");

  return `
    <div class="sample-table-wrap">
      <table class="sample-table">
        <thead>${head}</thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  `;
}

function renderMaliciousRecords(records) {
  if (!Array.isArray(records) || records.length === 0) return "";

  const columnOrder = [];
  const seen = new Set();
  for (const entry of records) {
    const row = entry.row_data || {};
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) {
        seen.add(key);
        columnOrder.push(key);
      }
    }
  }

  const head = `
    <tr>
      <th>#</th>
      ${columnOrder.map((c) => `<th>${escapeHtml(c)}</th>`).join("")}
    </tr>
  `;

  const body = records
    .map((entry) => {
      const row = entry.row_data || {};
      const cells = columnOrder
        .map((c) => {
          const value = row[c];
          const text =
            value == null
              ? ""
              : typeof value === "object"
                ? JSON.stringify(value)
                : String(value);
          return `<td>${escapeHtml(text)}</td>`;
        })
        .join("");
      return `<tr><td class="row-num">${escapeHtml(
        String(entry.connection_number ?? entry.row_index + 1),
      )}</td>${cells}</tr>`;
    })
    .join("");

  return `
    <div class="malicious-records">
      <strong>Malicious records</strong> (from stored CSV):
      <div class="sample-table-wrap">
        <table class="sample-table malicious-table">
          <thead>${head}</thead>
          <tbody>${body}</tbody>
        </table>
      </div>
    </div>
  `;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function readCsvHead(file, maxRecords = 10) {
  const SLICE_BYTES = 256 * 1024;
  const blob = file.size > SLICE_BYTES ? file.slice(0, SLICE_BYTES) : file;
  const text = await blob.text();
  return parseCsvHead(text, maxRecords);
}

function parseCsvHead(text, maxRecords) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  const rows = [];
  let field = "";
  let row = [];
  let inQuotes = false;
  const target = maxRecords + 1;
  for (let i = 0; i < text.length && rows.length < target; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      row.push(field);
      rows.push(row);
      field = "";
      row = [];
      if (ch === "\r" && text[i + 1] === "\n") i++;
    } else {
      field += ch;
    }
  }
  if (rows.length < target && (field !== "" || row.length > 0)) {
    row.push(field);
    rows.push(row);
  }

  if (rows.length === 0) return { headers: [], records: [] };
  const headers = rows[0];
  const records = rows.slice(1, target).map((r) => {
    const obj = {};
    for (let c = 0; c < headers.length; c++) {
      obj[headers[c]] = r[c] != null ? r[c] : "";
    }
    return obj;
  });
  return { headers, records };
}

async function previewLocalCsv(file) {
  const gen = claimResults();
  setResultsTitle(TITLE_PRE_RESULTS);
  const lower = (file.name || "").toLowerCase();
  if (!lower.endsWith(".csv")) {
    if (gen !== resultsGeneration) return;
    resultsBody.innerHTML = `
      <p>
        <strong>${escapeHtml(file.name)}</strong> selected.
        Local preview is only available for <strong>.csv</strong> files.
        Click <strong>Analyze</strong> to send it to the server.
      </p>
    `;
    return;
  }

  resultsBody.innerHTML = "<p>Reading CSV preview…</p>";
  try {
    const { records } = await readCsvHead(file, 10);
    if (gen !== resultsGeneration) return;
    if (records.length === 0) {
      resultsBody.innerHTML =
        '<p class="error">No rows found in this CSV preview.</p>';
      return;
    }
    const sample = records.map((row_data, idx) => ({
      row_index: idx,
      row_data,
    }));
    resultsBody.innerHTML = `
      <p>
        <strong>${escapeHtml(file.name)}</strong> — local preview
        (first ${escapeHtml(String(records.length))} rows, not sent to the server).
      </p>
      ${renderSampleTable(sample)}
      <p><em>Click <strong>Analyze</strong> to run inference and save this file.</em></p>
    `;
  } catch (err) {
    if (gen !== resultsGeneration) return;
    resultsBody.innerHTML = `<p class="error">Could not read CSV preview: ${escapeHtml(String(err))}</p>`;
  }
}

analyzeBtn.addEventListener("click", () => analyze());

async function getCurrentUser({ refresh = false } = {}) {
  if (currentUser && !refresh) return currentUser;
  const resp = await fetch(`${API_BASE}/users/me`);
  if (resp.status === 404) {
    currentUser = null;
    return null;
  }
  if (!resp.ok) {
    throw new Error(`GET /users/me failed (${resp.status})`);
  }
  currentUser = await resp.json();
  return currentUser;
}

async function fetchLogsForUser(userId) {
  const resp = await fetch(
    `${API_BASE}/users/${encodeURIComponent(userId)}/logs`,
  );
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    const detail =
      typeof body.detail === "string" ? body.detail : JSON.stringify(body);
    throw new Error(`GET /users/${userId}/logs failed (${resp.status}): ${detail}`);
  }
  return await resp.json();
}

async function refreshPreviousLogs() {
  if (!prevLogsList) return;
  try {
    const user = await getCurrentUser({ refresh: true });
    if (!user) {
      renderPreviousLogsEmpty("No user yet — upload a file to get started.");
      return;
    }
    const logs = await fetchLogsForUser(user.id);
    renderPreviousLogs(logs);
  } catch (err) {
    console.error("Failed to load previous logs:", err);
    renderPreviousLogsError(String(err));
  }
}

function renderPreviousLogsEmpty(message) {
  prevLogsList.classList.add("is-loaded");
  prevLogsList.removeAttribute("aria-busy");
  prevLogsList.innerHTML = `<div class="log-empty">${escapeHtml(message)}</div>`;
}

function renderPreviousLogsError(message) {
  prevLogsList.classList.add("is-loaded");
  prevLogsList.removeAttribute("aria-busy");
  prevLogsList.innerHTML = `<div class="log-error">${escapeHtml(message)}</div>`;
}

function renderPreviousLogs(logs) {
  prevLogsList.classList.add("is-loaded");
  prevLogsList.removeAttribute("aria-busy");
  prevLogsList.innerHTML = "";

  if (!logs.length) {
    renderPreviousLogsEmpty("No previous logs yet.");
    return;
  }

  for (const log of logs) {
    const logData = log.log_data || {};
    const filename = logData.filename || `Log #${log.id}`;
    const created = log.created_at
      ? new Date(log.created_at).toLocaleString()
      : "";
    const analysisId =
      Array.isArray(log.analysis_ids) && log.analysis_ids.length
        ? log.analysis_ids[0]
        : null;

    const item = document.createElement("button");
    item.type = "button";
    item.className = "log-item";
    if (activeLogId === log.id) item.classList.add("is-active");
    item.dataset.logId = String(log.id);
    if (analysisId != null) item.dataset.analysisId = String(analysisId);
    item.innerHTML = `
      <span class="log-item-name">${escapeHtml(filename)}</span>
      <span class="log-item-meta">${escapeHtml(created)}</span>
    `;
    item.addEventListener("click", () => openLog(log, item));
    prevLogsList.appendChild(item);
  }
}

async function openLog(log, itemEl) {
  const gen = claimResults();
  const analysisId =
    Array.isArray(log.analysis_ids) && log.analysis_ids.length
      ? log.analysis_ids[0]
      : null;

  document
    .querySelectorAll(".log-item.is-active")
    .forEach((el) => el.classList.remove("is-active"));
  if (itemEl) itemEl.classList.add("is-active");
  activeLogId = log.id;

  if (analysisId == null) {
    resultsBody.innerHTML = `<p>Log #${escapeHtml(String(log.id))} has no associated analysis yet.</p>`;
    return;
  }

  try {
    resultsBody.innerHTML = "<p>Loading previous analysis…</p>";
    const analysis = await fetchAnalysisFromDb(analysisId);
    if (gen !== resultsGeneration) return;
    const filename =
      (log.log_data && log.log_data.filename) || `Log #${log.id}`;
    renderAnalysisFromDb(analysis, filename);
    setResultsTitle(TITLE_RESULTS);
    hasRenderedAnalysis = true;
    rememberLastAnalysis(analysis.id, filename);
  } catch (err) {
    if (gen !== resultsGeneration) return;
    resultsBody.innerHTML = `<p class="error">${escapeHtml(String(err))}</p>`;
  }
}

refreshPreviousLogs();
restoreLastAnalysis();
