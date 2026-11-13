"""The live dashboard page. It polls /api/dashboard, which reads SQLite on every request.

Names, paths and payload previews come from the code being scanned, so an attacker
chooses them. The script only ever inserts them with textContent, and the page's
Content-Security-Policy blocks any script without this response's nonce.
"""

from __future__ import annotations

POLL_MS = 2000


def content_security_policy(nonce: str) -> str:
    return (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )


def render_dashboard(nonce: str, max_upload_bytes: int) -> str:
    return (
        _PAGE.replace("__NONCE__", nonce)
        .replace("__POLL_MS__", str(POLL_MS))
        .replace("__MAX_UPLOAD__", str(max_upload_bytes))
    )


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AST Master dashboard</title>
<style nonce="__NONCE__">
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --card: #ffffff; --text: #1c2128; --muted: #5b6573; --line: #d9dee5; --track: #e7eaef;
  --critical: #b3261e; --high: #b45309; --medium: #8a6d00; --low: #5b6573; --safe: #1a7f4b; --info: #1d5fbf;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171b; --card: #1d2126; --text: #e8eaed; --muted: #a2abb6; --line: #343a42; --track: #2c3138;
    --critical: #ff8a80; --high: #f5a742; --medium: #e0c04c; --low: #a2abb6; --safe: #5ad19a; --info: #82b4ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main, header { max-width: 1180px; margin: 0 auto; padding: 16px; }
header { display: flex; flex-wrap: wrap; gap: 8px 20px; align-items: center; justify-content: space-between; padding-bottom: 0; }
h1 { font-size: 21px; margin: 0; }
h2 { font-size: 16px; margin: 0 0 10px; }
a { color: var(--info); }
nav a { margin-right: 14px; }
.live { color: var(--muted); font-size: 13px; }
.live b { color: var(--safe); font-weight: 600; }
.live.down b { color: var(--critical); }
section { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 16px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(128px, 1fr)); gap: 10px; margin-bottom: 16px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px; }
.tile strong { display: block; font-size: 24px; font-variant-numeric: tabular-nums; }
.tile span { color: var(--muted); font-size: 13px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12.5px; white-space: nowrap; }
th, td { padding: 7px 10px 7px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.badge { font-weight: 650; font-size: 12.5px; white-space: nowrap; }
.MALICIOUS, .critical, .failed, .interrupted { color: var(--critical); }
.SUSPICIOUS, .high { color: var(--high); }
.medium { color: var(--medium); }
.low, .UNKNOWN, .PENDING { color: var(--low); }
.SAFE { color: var(--safe); }
.running { color: var(--info); }
.meter { display: flex; align-items: center; gap: 8px; min-width: 130px; font-variant-numeric: tabular-nums; }
.track { flex: 1; height: 8px; background: var(--track); border-radius: 4px; overflow: hidden; }
.fill { height: 100%; background: var(--low); }
.fill.MALICIOUS { background: var(--critical); }
.fill.SUSPICIOUS { background: var(--high); }
.fill.SAFE { background: var(--safe); }
.sub { color: var(--muted); font-size: 12.5px; overflow-wrap: anywhere; }
code { display: block; max-height: 7.5em; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.path { overflow-wrap: anywhere; min-width: 150px; }
.filters { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; margin-bottom: 10px; font-size: 13.5px; color: var(--muted); }
select { font: inherit; color: var(--text); background: var(--card); border: 1px solid var(--line); border-radius: 5px; padding: 3px 6px; max-width: 100%; }
.empty { color: var(--muted); margin: 4px 0; }
.remove { font: inherit; font-size: 12.5px; color: var(--critical); background: none; border: 1px solid var(--line); border-radius: 5px; padding: 2px 8px; cursor: pointer; white-space: nowrap; }
.remove:hover { border-color: var(--critical); }
.remove:disabled { opacity: .5; cursor: default; }
.note { color: var(--muted); font-size: 13px; margin: 8px 0 0; }
[hidden] { display: none !important; }
#upload { border: 2px dashed var(--line); text-align: center; padding: 20px 16px; }
#upload.over { border-color: var(--info); }
#upload h2 { margin-bottom: 4px; }
#upload p { margin: 0 0 12px; color: var(--muted); }
.pick { display: inline-block; font-weight: 600; color: #fff; background: #1d5fbf; border-radius: 6px; padding: 8px 16px; margin: 0 4px 6px; cursor: pointer; }
.pick:focus-within { outline: 2px solid var(--info); outline-offset: 2px; }
.pick input { position: absolute; width: 1px; height: 1px; opacity: 0; }
#upload.busy .pick { opacity: .5; pointer-events: none; }
#upload-status { min-height: 1.5em; margin-top: 6px; overflow-wrap: anywhere; }
#upload-status.bad { color: var(--critical); }
/* On a narrow screen each payload becomes a card, so its preview needs no sideways scroll. */
@media (max-width: 640px) {
  #payloads thead { display: none; }
  #payloads table, #payloads tbody, #payloads tr, #payloads td { display: block; width: 100%; }
  #payloads tr { padding: 10px 0; border-bottom: 1px solid var(--line); }
  #payloads tr:last-child { border-bottom: 0; }
  #payloads td { border: 0; padding: 2px 0; }
  #payloads td:empty { display: none; }
}
</style>
</head>
<body>
<header>
  <h1>AST Master dashboard</h1>
  <div class="live" id="live" role="status"><b>Connecting</b></div>
  <nav><a href="/">Server folders</a><a href="/reports">All reports</a></nav>
</header>
<main>
  <section id="upload">
    <h2>Check a file or folder</h2>
    <p>Drop any file, folder or .zip anywhere on this page, or choose one. Nothing in it is run.</p>
    <label class="pick">Choose folder<input type="file" id="pick-folder" webkitdirectory multiple></label>
    <label class="pick">Choose files or .zip<input type="file" id="pick-files" multiple></label>
    <div id="upload-status" role="status"></div>
  </section>
  <div class="tiles" id="tiles"></div>
  <section id="running-section" hidden><h2>Running now</h2><div class="scroll" id="running"></div></section>
  <section><h2>Repository comparison</h2><div class="scroll" id="repos"></div>
    <p class="note">Each row is the latest finished scan. Risk ranks results for review and isn't a probability. SAFE only means no known pattern matched.</p></section>
  <section><h2>Detected payloads</h2>
    <div class="filters">
      <label>Repository <select id="repo-filter"><option value="">All</option></select></label>
      <label>Severity <select id="severity-filter">
        <option value="high">Critical and high</option><option value="critical">Critical only</option><option value="">All</option>
      </select></label>
      <span id="payload-count"></span>
    </div>
    <div class="scroll" id="payloads"></div></section>
  <section><h2>Recent scans</h2><div class="scroll" id="scans"></div></section>
</main>
<script nonce="__NONCE__">
"use strict";
const $ = id => document.getElementById(id);
// Every value is inserted as text, never as markup. See the note at the top of dashboard.py.
function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined && content !== null) {
    if (content instanceof Node) node.append(content);
    else node.textContent = clean(content);
  }
  return node;
}
// Direction overrides could make a hostile payload display as something harmless.
const clean = value => String(value).replace(/[\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]/g, "\\ufffd");
const badge = (text, kind) => el("span", "badge " + kind, text);
function when(seconds) {
  if (!seconds) return "-";
  const date = new Date(seconds * 1000), now = new Date();
  return date.toDateString() === now.toDateString() ? date.toLocaleTimeString() : date.toLocaleString();
}
function elapsed(seconds) {
  if (seconds < 1) return "<1 s";
  if (seconds < 90) return Math.round(seconds) + " s";
  if (seconds < 5400) return Math.round(seconds / 60) + " min";
  return Math.round(seconds / 3600) + " h";
}
function table(headers, rows) {
  const out = el("table"), head = el("tr");
  for (const header of headers) {
    const numeric = header.endsWith("#");
    head.append(el("th", numeric ? "num" : "", numeric ? header.slice(0, -1) : header));
  }
  const thead = el("thead"), tbody = el("tbody");
  thead.append(head);
  for (const cells of rows) {
    const row = el("tr");
    cells.forEach((cell, index) => {
      const numeric = headers[index].endsWith("#");
      row.append(cell instanceof Node ? wrap(cell) : el("td", numeric ? "num" : "", cell));
    });
    tbody.append(row);
  }
  out.append(thead, tbody);
  return out;
}
function wrap(node) { const td = el("td"); td.append(node); return td; }
function fill(target, node) { target.replaceChildren(node); }
function empty(text) { return el("p", "empty", text); }
function stack(top, bottom) {
  const box = el("div", "path");
  box.append(top instanceof Node ? top : el("div", "", top), el("div", "sub", bottom));
  return box;
}
function meter(score, verdict) {
  const box = el("div", "meter");
  if (score === null || score === undefined) { box.append(el("span", "sub", "not scored")); return box; }
  const track = el("div", "track"), bar = el("div", "fill " + verdict);
  bar.style.width = Math.min(100, Math.max(0, score)) + "%";
  track.append(bar);
  box.append(track, el("span", "", score));
  return box;
}
function reportLink(scan, text) {
  if (scan.status !== "complete") return el("div", "", text);
  const link = el("a", "", text);
  link.href = "/report/" + encodeURIComponent(scan.scan_id);
  return link;
}

function removeButton(what, question, url) {
  const button = el("button", "remove", "Remove");
  button.type = "button";
  button.setAttribute("aria-label", "Remove " + what);
  button.addEventListener("click", async () => {
    if (!window.confirm(question + "\\n\\nThis can't be undone.")) return;
    button.disabled = true;
    try {
      const reply = await fetch(url, {method: "DELETE"});
      if (!reply.ok && reply.status !== 404) window.alert((await reply.text()).trim());
    } catch (error) {
      window.alert("Couldn't reach the server, so nothing was removed.");
    }
    button.disabled = false;
    lastBody = "";
    poll();
  });
  return button;
}
function renderTiles(data) {
  const s = data.summary;
  const tiles = [
    [s.repositories, "Repositories"], [s.scans, "Finished scans"], [s.malicious, "Malicious scans"],
    [s.suspicious, "Suspicious scans"], [s.safe, "Safe scans"], [s.critical_payloads, "Critical payloads, latest scans"],
  ];
  $("tiles").replaceChildren(...tiles.map(([value, label]) => {
    const tile = el("div", "tile");
    tile.append(el("strong", "", value), el("span", "", label));
    return tile;
  }));
}
function renderRunning(data) {
  const running = data.scans.filter(scan => scan.status === "running");
  $("running-section").hidden = !running.length;
  if (!running.length) return;
  const stages = {walking: "Reading files", phase2: "AST analysis", phase3: "Comparing with signatures"};
  fill($("running"), table(["Repository", "Stage", "Files#", "Findings#", "Running for"], running.map(scan => [
    scan.name, stages[scan.stage] || scan.stage, scan.files, scan.findings, elapsed(data.now - scan.created_at),
  ])));
}
function renderRepos(data) {
  if (!data.repositories.length) return fill($("repos"), empty("Nothing checked yet. Upload a file or folder above to start."));
  fill($("repos"), table(
    ["Repository", "Verdict", "Risk", "Files#", "Critical#", "High#", "Medium#", "Low#", "Payloads#", "Scans#", "Last finished", ""],
    data.repositories.map(repo => [
      stack(repo.name, repo.root),
      repo.last_verdict ? badge(repo.last_verdict, repo.last_verdict) : el("span", "sub", "no finished scan"),
      meter(repo.last_risk_score, repo.last_verdict), repo.files, repo.critical, repo.high, repo.medium, repo.low,
      repo.payloads, repo.scans, when(repo.finished_at),
      removeButton(clean(repo.name), "Delete " + clean(repo.name) + " and all of its scans and alerts from the database?", "/api/repositories/" + repo.repo_id),
    ]),
  ));
}
function renderPayloads(data) {
  const select = $("repo-filter"), names = [...new Set(data.payloads.map(p => p.repository))].sort();
  const current = [...select.options].slice(1).map(o => o.value);
  if (names.join("\\0") !== current.join("\\0")) {
    const chosen = select.value;
    select.replaceChildren(el("option", "", "All"), ...names.map(name => el("option", "", name)));
    select.options[0].value = "";
    names.forEach((name, index) => { select.options[index + 1].value = name; });
    select.value = names.includes(chosen) ? chosen : "";
  }
  const level = $("severity-filter").value;
  const allowed = {critical: ["critical"], high: ["critical", "high"], "": ["critical", "high", "medium", "low"]}[level];
  const shown = data.payloads.filter(p => allowed.includes(p.severity) && (!select.value || p.repository === select.value));
  const known = data.payloads_total > data.payloads.length ? ", newest " + data.payloads.length + " of " + data.payloads_total + " loaded" : "";
  $("payload-count").textContent = "Showing " + shown.length + " of " + data.payloads_total + known;
  if (!shown.length) {
    return fill($("payloads"), empty(data.payloads.length ? "No payloads match these filters. Set Severity to All to see lower ones." : "No payloads in the latest scans."));
  }
  fill($("payloads"), table(["Severity", "Repository", "File", "Type", "Encoding", "Preview", ""], shown.map(p => [
    badge(p.severity, p.severity), p.repository,
    stack(p.path, "line " + p.line + ", " + p.rule), p.kind, p.encoding || "-", el("code", "", p.preview),
    removeButton("alert in " + clean(p.path), "Remove this alert from the database?\\n\\n" + clean(p.path) + ", line " + p.line + "\\n\\nThe scan's verdict stays the same, and scanning the folder again will find this again.", "/api/payloads/" + p.payload_id),
  ])));
}
function renderScans(data) {
  if (!data.scans.length) return fill($("scans"), empty("No scans yet."));
  fill($("scans"), table(
    ["Repository", "Status", "Verdict", "Risk", "Files#", "Findings#", "Payloads#", "Took", "Started", ""],
    data.scans.map(scan => [
      stack(reportLink(scan, scan.name), (scan.error || scan.source) + (scan.removed_alerts ? ", " + scan.removed_alerts + " alert(s) removed" : "")),
      badge(scan.status, scan.status), badge(scan.verdict, scan.verdict), meter(scan.risk_score, scan.verdict),
      scan.files, scan.findings, scan.payloads, scan.finished_at ? elapsed(scan.finished_at - scan.created_at) : "-", when(scan.created_at),
      scan.status === "running" ? "" : removeButton("scan of " + clean(scan.name), "Delete this scan of " + clean(scan.name) + " and all of its results from the database?", "/api/scans/" + encodeURIComponent(scan.scan_id)),
    ]),
  ));
}
let lastBody = "", lastData = null;
function draw() {
  if (!lastData) return;
  renderTiles(lastData); renderRunning(lastData); renderRepos(lastData); renderPayloads(lastData); renderScans(lastData);
}
async function poll() {
  const live = $("live");
  try {
    const reply = await fetch("/api/dashboard", {cache: "no-store"});
    if (!reply.ok) throw new Error("HTTP " + reply.status);
    const body = await reply.text();
    // Redraw only on a change, so an idle page keeps its scroll position and text selection.
    const parsed = JSON.parse(body), stamp = body.replace(/"now": [0-9.]+,?/, "");
    lastData = parsed;
    const hasRunning = parsed.scans.some(scan => scan.status === "running");
    if (stamp !== lastBody || hasRunning) { lastBody = stamp; draw(); }
    live.className = "live";
    live.replaceChildren(el("b", "", "Live"), document.createTextNode(", checked " + new Date().toLocaleTimeString()));
  } catch (error) {
    live.className = "live down";
    live.replaceChildren(el("b", "", "Not connected"), document.createTextNode(lastData ? ". Showing the last data received. Retrying." : ". Retrying."));
  }
}

// ---- Upload: any file or folder. The results arrive through the same SQLite polling.
const MAX_UPLOAD = __MAX_UPLOAD__;
const SKIPPED = /(^|\\/)(\\.git|__pycache__)\\//;  // A folder scan on the server skips these too.
let uploading = false;
function status(text, bad) {
  const box = $("upload-status");
  box.className = bad ? "bad" : "";
  box.textContent = clean(text);
  return box;
}
function setBusy(busy) {
  uploading = busy;
  $("upload").classList.toggle("busy", busy);
  $("pick-folder").disabled = busy;
  $("pick-files").disabled = busy;
}
async function showResult(scanId) {
  await poll();
  const scan = lastData && lastData.scans.find(item => item.scan_id === scanId);
  const box = status("");
  if (!scan) { box.textContent = "Checked. The result is in Recent scans below."; return; }
  const link = el("a", "", "Open full report");
  link.href = "/report/" + encodeURIComponent(scanId);
  if (!scan.files) {
    box.className = "bad";
    box.append(clean(scan.name) + ": nothing was checked, because it has no Python or packaging files. ");
  } else {
    box.append(clean(scan.name) + ": ", badge(scan.verdict, scan.verdict),
      ", risk " + scan.risk_score + "/100, " + scan.files + " file(s) checked. ");
  }
  box.append(link);
}
function sendUpload(pairs) {
  if (uploading) return;
  pairs = pairs.filter(([, path]) => !SKIPPED.test(path));
  if (!pairs.length) return status("That has no files to check.", true);
  const total = pairs.reduce((sum, [file]) => sum + file.size, 0);
  if (total > MAX_UPLOAD) {
    return status("That is " + Math.ceil(total / 1048576) + " MB. The limit is " + Math.floor(MAX_UPLOAD / 1048576) + " MB.", true);
  }
  const archive = pairs.length === 1 && pairs[0][1].toLowerCase().endsWith(".zip");
  const body = new FormData();
  for (const [file, path] of pairs) body.append(archive ? "archive" : "files", file, path);
  const request = new XMLHttpRequest();
  setBusy(true);
  const count = pairs.length + " file(s)";
  status("Uploading " + count + "...");
  request.upload.onprogress = event => {
    if (event.lengthComputable) status("Uploading " + count + ": " + Math.round(event.loaded * 100 / event.total) + "%");
  };
  request.upload.onload = () => status("Checking " + count + "...");
  request.onload = () => {
    setBusy(false);
    const match = /\\/report\\/([^/?#]+)$/.exec(request.responseURL);
    if (request.status === 200 && match) showResult(decodeURIComponent(match[1]));
    else status("Upload failed: " + request.responseText.trim().slice(0, 200), true);
  };
  request.onerror = () => { setBusy(false); status("Upload failed: the server didn't finish the request.", true); };
  request.open("POST", "/upload-folder");
  request.send(body);
}
function pickFrom(input) {
  input.addEventListener("change", () => {
    const files = [...input.files];
    if (files.length) sendUpload(files.map(file => [file, file.webkitRelativePath || file.name]));
    input.value = "";
  });
}
pickFrom($("pick-folder"));
pickFrom($("pick-files"));
const readBatch = reader => new Promise((done, fail) => reader.readEntries(done, fail));
async function walk(entry, path, out) {
  if (entry.isFile) {
    out.push([await new Promise((done, fail) => entry.file(done, fail)), path + entry.name]);
    return;
  }
  const reader = entry.createReader();
  for (let batch = await readBatch(reader); batch.length; batch = await readBatch(reader)) {
    for (const child of batch) await walk(child, path + entry.name + "/", out);
  }
}
addEventListener("dragover", event => { event.preventDefault(); $("upload").classList.add("over"); });
addEventListener("dragleave", event => { if (!event.relatedTarget) $("upload").classList.remove("over"); });
addEventListener("drop", async event => {
  event.preventDefault();
  $("upload").classList.remove("over");
  if (uploading) return;
  const entries = [...event.dataTransfer.items].map(item => item.webkitGetAsEntry()).filter(Boolean);
  const out = [];
  try {
    for (const entry of entries) await walk(entry, "", out);
  } catch (error) {
    return status("Couldn't read that folder in the browser.", true);
  }
  if (out.length) sendUpload(out);
  else status("That folder is empty.", true);
});

$("repo-filter").addEventListener("change", draw);
$("severity-filter").addEventListener("change", draw);
async function loop() {
  if (!document.hidden) await poll();
  setTimeout(loop, __POLL_MS__);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
loop();
</script>
</body>
</html>
"""
