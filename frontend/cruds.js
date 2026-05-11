const API_BASE = "http://127.0.0.1:8000";

const fileInput = document.getElementById("fileInput");
const fileLabel = document.getElementById("fileLabel");
const analyzeBtn = document.getElementById("analyzeBtn");
const uploadCard = document.getElementById("uploadCard");
const resultsBody = document.getElementById("resultsBody");
const newInvBtn = document.getElementById("newInvBtn");

const PLACEHOLDER_TEXT = "data.pcap";

function setFileLabel(name) {
  fileLabel.textContent = name || PLACEHOLDER_TEXT;
  fileLabel.classList.toggle("has-file", Boolean(name));
}

function resetResultsPlaceholder() {
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
});

newInvBtn.addEventListener("click", () => {
  fileInput.value = "";
  setFileLabel(null);
  resetResultsPlaceholder();
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
});

async function analyze() {
  const file = fileInput.files[0];
  if (!file) {
    alert("Please choose a file first (click the field or drop a file).");
    return;
  }
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
    const response = await fetch(`${API_BASE}/upload-csv`, {
      method: "POST",
      body: formData,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail =
        typeof result.detail === "string"
          ? result.detail
          : JSON.stringify(result.detail || result);
      resultsBody.innerHTML = `<p class="error">Request failed (${response.status})</p><pre class="json">${escapeHtml(detail)}</pre>`;
      return;
    }

    const inf = result.malware_identification || {};
    const malwareCount = inf.malware_count ?? "—";
    const rows = result.rows ?? inf.rows ?? "—";
    const threshold = result.threshold ?? "—";
    const preview = result.preview ? JSON.stringify(result.preview, null, 2) : "";

    resultsBody.innerHTML = `
      <p>Analysis complete for <strong>${escapeHtml(result.filename || file.name)}</strong>.</p>
      <div class="stats">
        <div><strong>Rows</strong>: ${escapeHtml(String(rows))}</div>
        <div><strong>Malware count</strong> (by threshold): ${escapeHtml(String(malwareCount))}</div>
        <div><strong>Threshold</strong>: ${escapeHtml(String(threshold))}</div>
        <div><strong>Feature columns used</strong>: ${escapeHtml(JSON.stringify(result.feature_columns_used || []))}</div>
      </div>
      <p><strong>Preview</strong> (first rows, raw CSV columns):</p>
      <pre class="json">${escapeHtml(preview || "{}")}</pre>
      <p><strong>Full response</strong> (for debugging):</p>
      <pre class="json">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
    `;
  } catch (err) {
    resultsBody.innerHTML = `<p class="error">Network error — is the API running at ${API_BASE}?</p><pre class="json">${escapeHtml(String(err))}</pre>`;
  } finally {
    analyzeBtn.disabled = false;
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

analyzeBtn.addEventListener("click", analyze);
