pub const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MCP and Agent Workbench</title>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #111827;
      --panel-alt: #1f2937;
      --border: #374151;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --ok: #22c55e;
      --warn: #f59e0b;
      --err: #ef4444;
      --purple: #a855f7;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
    }
    #full-capture-banner {
      display: none;
      background: #7c2d12;
      color: #fed7aa;
      padding: 8px 16px;
      font-weight: 600;
      text-align: center;
      border-bottom: 1px solid #f97316;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 20px;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 16px;
      font-weight: 700;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      background: var(--panel-alt);
      color: var(--muted);
      border: 1px solid var(--border);
    }
    .badge.ok { color: #86efac; border-color: #166534; background: #052e16; }
    .badge.warn { color: #fde68a; border-color: #92400e; background: #451a03; }
    .badge.err { color: #fca5a5; border-color: #991b1b; background: #450a0a; }
    .badge.info { color: #7dd3fc; border-color: #075985; background: #082f49; }
    nav {
      display: flex;
      gap: 6px;
      padding: 0 20px;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
    }
    nav button {
      background: transparent;
      color: var(--muted);
      border: none;
      border-bottom: 2px solid transparent;
      padding: 10px 14px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
    }
    nav button.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }
    main {
      padding: 16px 20px;
      max-width: 1600px;
      margin: 0 auto;
    }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
    .grid-2 {
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 16px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 14px;
    }
    .card h3 {
      margin: 0 0 10px 0;
      font-size: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    input, select, textarea {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 10px;
      font-size: 13px;
    }
    button.btn {
      background: var(--accent);
      color: #000;
      border: none;
      border-radius: 6px;
      padding: 6px 12px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
    }
    button.btn.secondary {
      background: var(--panel-alt);
      color: var(--text);
      border: 1px solid var(--border);
    }
    .run-item {
      padding: 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      margin-bottom: 8px;
      cursor: pointer;
      background: var(--bg);
    }
    .run-item.selected {
      border-color: var(--accent);
      background: #0c192c;
    }
    .span-row {
      display: grid;
      grid-template-columns: 240px 110px 1fr 90px;
      align-items: center;
      gap: 10px;
      padding: 7px 10px;
      border-bottom: 1px solid #1f2937;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .span-row:hover { background: var(--panel-alt); }
    .span-row.selected { background: #172554; }
    .bar-track {
      background: #1f2937;
      height: 10px;
      border-radius: 5px;
      position: relative;
      overflow: hidden;
    }
    .bar-fill {
      height: 100%;
      border-radius: 5px;
      background: var(--accent);
    }
    .bar-fill.error, .bar-fill.blocked { background: var(--err); }
    .bar-fill.waiting_human { background: var(--warn); }
    .bar-fill.llm { background: var(--purple); }
    pre {
      background: #050811;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      overflow-x: auto;
      font-family: var(--font-mono);
      font-size: 12px;
      margin: 6px 0;
      max-height: 360px;
    }
    .xray-bar {
      display: flex;
      height: 20px;
      border-radius: 6px;
      overflow: hidden;
      margin: 8px 0;
      border: 1px solid var(--border);
    }
    .xray-seg-sys { background: #3b82f6; }
    .xray-seg-tools { background: #a855f7; }
    .xray-seg-user { background: #10b981; }
    .xray-seg-asst { background: #06b6d4; }
    .xray-seg-res { background: #f59e0b; }
    .diff-row {
      display: grid;
      grid-template-columns: 50px 1fr 1fr;
      gap: 10px;
      padding: 8px;
      border-bottom: 1px solid var(--border);
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .diff-row.diverged {
      background: #450a0a;
      border-left: 4px solid var(--err);
    }
  </style>
</head>
<body>
  <div id="full-capture-banner">
    FULL PAYLOAD CAPTURE IS ACTIVE — Redacted tool arguments, results, and prompts are being persisted to local SQLite.
  </div>
  <header>
    <div class="brand">
      <span>MCP &amp; Agent Workbench</span>
      <span id="capture-badge" class="badge info">capture: metadata</span>
      <span id="price-date-badge" class="badge">pricing: 2026-11-01</span>
      <span id="dropped-badge" class="badge ok">dropped: 0</span>
    </div>
    <div style="display:flex; gap:8px; align-items:center;">
      <button id="btn-refresh" class="btn secondary">Refresh</button>
    </div>
  </header>
  <nav id="main-nav">
    <button class="active" data-tab="timeline">1. Runs &amp; Timeline</button>
    <button data-tab="catalog">2. Server Catalog &amp; Manual Call</button>
    <button data-tab="xray">3. Context Window X-Ray</button>
    <button data-tab="breaker">4. Cost &amp; Circuit Breaker</button>
    <button data-tab="policy">5. Policy &amp; Firewall</button>
    <button data-tab="export">6. Export &amp; Replay</button>
  </nav>

  <main>
    <!-- TAB 1: RUNS & TIMELINE -->
    <section id="tab-timeline" class="tab-pane active">
      <div class="grid-2">
        <div>
          <div class="card">
            <h3>
              <span>Recorded Runs</span>
              <select id="run-status-filter">
                <option value="">All statuses</option>
                <option value="ok">ok</option>
                <option value="error">error</option>
              </select>
            </h3>
            <div id="runs-list">Loading runs...</div>
          </div>

          <div class="card">
            <h3>Run Diff (Compare Two Runs)</h3>
            <div style="display:flex; flex-direction:column; gap:8px;">
              <select id="diff-left"></select>
              <select id="diff-right"></select>
              <button id="btn-run-diff" class="btn secondary">Compare Runs</button>
            </div>
          </div>
        </div>

        <div>
          <div id="diff-view-card" class="card" style="display:none;">
            <h3>
              <span>Run Diff Comparison</span>
              <button id="btn-close-diff" class="btn secondary">Close</button>
            </h3>
            <div id="diff-summary" style="margin-bottom:10px;"></div>
            <div id="diff-entries"></div>
          </div>

          <div class="card">
            <h3>
              <span id="timeline-title">Run Timeline</span>
              <div style="display:flex; gap:6px;">
                <input id="span-filter" placeholder="Filter tool / method / server..." />
                <select id="span-status-filter">
                  <option value="">All</option>
                  <option value="ok">ok</option>
                  <option value="error">error</option>
                  <option value="waiting_human">waiting_human</option>
                  <option value="blocked">blocked</option>
                </select>
              </div>
            </h3>
            <div id="spans-container" style="max-height:420px; overflow-y:auto;">Select a run to inspect its timeline.</div>
          </div>

          <div id="inspector-card" class="card" style="display:none;">
            <h3>
              <span id="inspector-title">Message Inspector</span>
              <div>
                <button id="btn-inspector-pretty" class="btn secondary" data-inspector-mode="pretty">Pretty</button>
                <button id="btn-inspector-raw" class="btn secondary" data-inspector-mode="raw">Raw Wire</button>
              </div>
            </h3>
            <div id="inspector-body"></div>
            <div style="margin-top:12px; border-top:1px solid var(--border); padding-top:10px;">
              <h4>Annotations</h4>
              <div id="inspector-annotations"></div>
              <div style="display:flex; gap:6px; margin-top:6px;">
                <input id="ann-author" placeholder="Author" value="dev" style="width:100px;" />
                <input id="ann-text" placeholder="Add a note to this span..." style="flex:1;" />
                <button id="btn-submit-annotation" class="btn">Add Note</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 2: SERVER CATALOG & MANUAL CALL -->
    <section id="tab-catalog" class="tab-pane">
      <div class="grid-2">
        <div class="card">
          <h3>Discovered MCP Servers</h3>
          <div id="servers-list">Loading servers...</div>
        </div>
        <div>
          <div class="card">
            <h3 id="catalog-server-title">Server Tool Catalog</h3>
            <div id="tools-list">Select a server to view its exposed tools, schema hashes, and change history.</div>
          </div>
          <div class="card">
            <h3>Manual Tool Call Panel</h3>
            <div id="manual-call-container">Select a tool above to generate a schema form or raw JSON invoker.</div>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 3: CONTEXT WINDOW X-RAY -->
    <section id="tab-xray" class="tab-pane">
      <div class="card">
        <h3>Context Window X-Ray (Per-Model Call Token Composition)</h3>
        <p style="color:var(--muted); margin-top:0;">
          Tracks token distribution across System Prompt, Tool Definitions, Conversation History, and Tool Results.
        </p>
        <div id="xray-container">Select a run in Tab 1 to inspect its Context Window X-Ray profile.</div>
      </div>
    </section>

    <!-- TAB 4: COST & CIRCUIT BREAKER -->
    <section id="tab-breaker" class="tab-pane">
      <div class="grid-2">
        <div class="card">
          <h3>Circuit Breaker Status &amp; Guardrails</h3>
          <div id="breaker-status"></div>
        </div>
        <div class="card">
          <h3>Live Cost Accounting</h3>
          <p style="color:var(--muted); margin-top:0;">
            Formula: <code>(input - cached) * input_price + cached * cache_price + output * output_price</code>.
            Numbers prefixed with <code>~</code> indicate fallback tokenizer estimates when a provider stream omitted <code>usage</code>.
          </p>
          <div id="cost-summary"></div>
        </div>
      </div>
    </section>

    <!-- TAB 5: POLICY & FIREWALL -->
    <section id="tab-policy" class="tab-pane">
      <div class="grid-2">
        <div class="card">
          <h3>Transport Policy Rules</h3>
          <div style="margin-bottom:10px;">
            <label><input type="checkbox" id="policy-enabled-toggle" /> Enforce Policy Firewall (Fail-Closed)</label>
            <div style="color:var(--muted); font-size:12px; margin-top:4px;">
              Applies to <code>wb wrap</code> processes started after saving. Restart your MCP client to pick up a change in already-running wrappers.
            </div>
          </div>
          <textarea id="policy-rules-editor" rows="10" style="width:100%; font-family:var(--font-mono);"></textarea>
          <div style="margin-top:8px;">
            <button id="btn-save-policies" class="btn">Save Policy Rules</button>
          </div>
          <hr style="border-color:var(--border); margin:14px 0;" />
          <h3>Interactive Policy Tester</h3>
          <div style="display:flex; flex-direction:column; gap:6px;">
            <input id="ptest-server" placeholder="Server ID (e.g. filesystem)" value="filesystem" />
            <input id="ptest-tool" placeholder="Tool Name (e.g. write_file)" value="write_file" />
            <input id="ptest-args" placeholder='Arguments JSON (e.g. {"path":"/etc/passwd"})' value='{"path":"/etc/passwd"}' />
            <button id="btn-run-policy-test" class="btn secondary">Test Call Against Policy</button>
            <pre id="ptest-result" style="display:none;"></pre>
          </div>
        </div>
        <div class="card">
          <h3>Policy Audit Trail (Metadata Only)</h3>
          <div id="policy-decisions-list">No policy decisions recorded yet.</div>
        </div>
      </div>
    </section>

    <!-- TAB 6: EXPORT & REPLAY -->
    <section id="tab-export" class="tab-pane">
      <div class="grid-2">
        <div class="card">
          <h3>Export Runs (with Redaction Preview)</h3>
          <div style="display:flex; flex-direction:column; gap:8px;">
            <label>Format:</label>
            <select id="export-format">
              <option value="jsonl">JSONL (Reproducible Run Archive)</option>
              <option value="otlp">OpenTelemetry OTLP/JSON (Jaeger / Collector)</option>
              <option value="mockmcp">MockMCP Studio Replay Fixtures</option>
            </select>
            <div style="display:flex; gap:8px; margin-top:6px;">
              <button id="btn-preview-export" class="btn secondary">Preview Exact Bytes</button>
              <button id="btn-download-export" class="btn">Download Export</button>
            </div>
            <pre id="export-preview-box" style="display:none; max-height:400px;"></pre>
          </div>
        </div>
        <div class="card">
          <h3>Import JSONL Run Archive</h3>
          <textarea id="import-jsonl-box" rows="8" style="width:100%; font-family:var(--font-mono);" placeholder="Paste exported JSONL lines here..."></textarea>
          <div style="margin-top:8px;">
            <button id="btn-import-jsonl" class="btn">Import Run</button>
            <span id="import-status" style="margin-left:10px; color:var(--ok);"></span>
          </div>
        </div>
      </div>
    </section>
  </main>

  <script src="/app.js"></script>
</body>
</html>
"#;

pub const APP_JS: &str = r#"const urlParams = new URLSearchParams(window.location.search);
const urlToken = urlParams.get('token') || '';
let currentRuns = [];
let selectedRunId = null;
let currentSpans = [];
let selectedSpanDetail = null;
let inspectorMode = 'pretty';
let priceTableDate = '2026-11-01';
let currentServerTools = [];
let selectedServerId = null;

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function apiFetch(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (urlToken) {
    headers['X-WB-Token'] = urlToken;
  }
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(txt || res.statusText);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

function switchTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(el => el.classList.remove('active'));
  const pane = document.getElementById('tab-' + name);
  if (pane) pane.classList.add('active');
  if (btn) btn.classList.add('active');
}

async function loadStatus() {
  try {
    const st = await apiFetch('/api/status');
    priceTableDate = st.price_table_date;
    document.getElementById('capture-badge').textContent = 'capture: ' + st.capture_level;
    document.getElementById('price-date-badge').textContent = 'pricing: ' + st.price_table_date;
    const dropEl = document.getElementById('dropped-badge');
    dropEl.textContent = 'dropped: ' + st.dropped_events;
    dropEl.className = 'badge ' + (st.dropped_events > 0 ? 'err' : 'ok');
    document.getElementById('full-capture-banner').style.display = st.full_capture_banner ? 'block' : 'none';

    const brk = st.modules.circuit_breaker;
    document.getElementById('breaker-status').innerHTML = `
      <p><strong>Status:</strong> <span class="badge ${brk.enabled ? 'ok' : 'warn'}">${brk.enabled ? 'Active' : 'Disabled'}</span></p>
      <p><strong>Max Run Cost Ceiling:</strong> $${Number(brk.max_run_cost_usd).toFixed(2)} <span class="badge">table: ${escapeHtml(st.price_table_date)}</span></p>
      <p><strong>Max Run Tokens Ceiling:</strong> ${Number(brk.max_run_tokens).toLocaleString()} tokens</p>
      <p><strong>Max Identical Tool Call Loop Threshold:</strong> ${Number(brk.max_identical_tool_calls)} consecutive calls</p>
    `;
  } catch (e) {
    console.error('Status error:', e);
  }
}

async function loadRuns() {
  try {
    const statusFilter = document.getElementById('run-status-filter').value;
    const q = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : '';
    currentRuns = await apiFetch('/api/runs' + q);
    const listEl = document.getElementById('runs-list');
    if (!currentRuns.length) {
      listEl.innerHTML = '<p style="color:var(--muted);">No runs recorded yet.</p>';
      return;
    }
    if (!selectedRunId && currentRuns.length > 0) {
      selectedRunId = currentRuns[0].id;
    }
    listEl.innerHTML = currentRuns.map(r => {
      const costPrefix = r.estimated_cost ? '~' : '';
      const statusClass = r.status === 'ok' ? 'ok' : 'err';
      const displayLabel = escapeHtml(r.label || String(r.id).slice(0, 14));
      return `
        <div class="run-item ${r.id === selectedRunId ? 'selected' : ''}" data-run-id="${escapeHtml(r.id)}">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong>${displayLabel}</strong>
            <span class="badge ${statusClass}">${escapeHtml(r.status)}</span>
          </div>
          <div style="margin-top:4px; font-size:12px; color:var(--muted); display:flex; justify-content:space-between;">
            <span>${Number(r.span_count)} spans (${Number(r.error_count)} err)</span>
            <span>${costPrefix}$${Number(r.total_cost_usd).toFixed(4)} <small>[${escapeHtml(priceTableDate)}]</small></span>
          </div>
        </div>
      `;
    }).join('');

    // Populate diff dropdowns safely
    const opts = currentRuns.map(r => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.label || String(r.id).slice(0, 16))} ($${Number(r.total_cost_usd).toFixed(4)})</option>`).join('');
    document.getElementById('diff-left').innerHTML = opts;
    document.getElementById('diff-right').innerHTML = opts;
    if (currentRuns.length > 1) {
      document.getElementById('diff-right').selectedIndex = 1;
    }

    // Render cost summary in Tab 4
    const totalCost = currentRuns.reduce((acc, r) => acc + Number(r.total_cost_usd || 0), 0);
    document.getElementById('cost-summary').innerHTML = `
      <p><strong>Total Recorded Cost (${currentRuns.length} runs):</strong> $${totalCost.toFixed(4)} <span class="badge">price table: ${escapeHtml(priceTableDate)}</span></p>
    `;

    if (selectedRunId) {
      await loadRunSpans(selectedRunId);
    }
  } catch (e) {
    console.error('Load runs error:', e);
  }
}

async function selectRun(runId) {
  selectedRunId = runId;
  await loadRuns();
}

async function loadRunSpans(runId) {
  currentSpans = await apiFetch(`/api/runs/${encodeURIComponent(runId)}/spans`);
  renderSpans();
  loadRunXray(runId);
}

function renderSpans() {
  const container = document.getElementById('spans-container');
  const filterTxt = (document.getElementById('span-filter').value || '').toLowerCase();
  const statusFilter = document.getElementById('span-status-filter').value;

  const filtered = currentSpans.filter(s => {
    if (statusFilter && s.status !== statusFilter) return false;
    if (!filterTxt) return true;
    const hay = (s.name + ' ' + JSON.stringify(s.attributes || {})).toLowerCase();
    return hay.includes(filterTxt);
  });

  if (!filtered.length) {
    container.innerHTML = '<p style="color:var(--muted);">No matching spans.</p>';
    return;
  }

  const minStart = Math.min(...filtered.map(s => s.start_ns));
  const maxEnd = Math.max(...filtered.map(s => s.end_ns || s.start_ns + 1000000));
  const totalWindow = Math.max(1, maxEnd - minStart);

  container.innerHTML = filtered.map(s => {
    const durMs = s.end_ns ? ((s.end_ns - s.start_ns) / 1e6).toFixed(2) + ' ms' : 'in-flight';
    const leftPct = Math.min(95, Math.max(0, ((s.start_ns - minStart) / totalWindow) * 100));
    const widthPct = Math.max(3, Math.min(100 - leftPct, (((s.end_ns || maxEnd) - s.start_ns) / totalWindow) * 100));
    const statusBadge = s.status === 'waiting_human'
      ? '<span class="badge warn">waiting on human</span>'
      : `<span class="badge ${s.status === 'ok' ? 'ok' : 'err'}">${escapeHtml(s.status)}</span>`;
    const barClass = escapeHtml(s.status !== 'ok' ? s.status : s.kind);
    return `
      <div class="span-row" data-span-id="${escapeHtml(s.id)}">
        <div><strong>${escapeHtml(s.name)}</strong></div>
        <div>${statusBadge}</div>
        <div class="bar-track">
          <div class="bar-fill ${barClass}" style="margin-left:${leftPct}%; width:${widthPct}%;"></div>
        </div>
        <div style="text-align:right; color:var(--muted);">${durMs}</div>
      </div>
    `;
  }).join('');
}

async function inspectSpan(spanId) {
  selectedSpanDetail = await apiFetch(`/api/spans/${encodeURIComponent(spanId)}`);
  document.getElementById('inspector-card').style.display = 'block';
  renderInspector();
}

function setInspectorMode(mode) {
  inspectorMode = mode;
  renderInspector();
}

function renderInspector() {
  if (!selectedSpanDetail) return;
  const sp = selectedSpanDetail.span;
  document.getElementById('inspector-title').textContent = `Span: ${sp.name} (${String(sp.id).slice(0, 14)})`;
  let html = `<p><strong>Status:</strong> ${escapeHtml(sp.status)} | <strong>Kind:</strong> ${escapeHtml(sp.kind)} | <strong>Trace:</strong> <code>${escapeHtml(sp.trace_id)}</code></p>`;
  html += `<h4>OpenTelemetry Span Attributes</h4><pre>${escapeHtml(JSON.stringify(sp.attributes, null, 2))}</pre>`;

  if (selectedSpanDetail.mcp_messages && selectedSpanDetail.mcp_messages.length) {
    html += `<h4>JSON-RPC Wire Messages (${selectedSpanDetail.mcp_messages.length})</h4>`;
    for (const m of selectedSpanDetail.mcp_messages) {
      let body = m.payload || '(payload omitted by capture level)';
      if (inspectorMode === 'pretty' && m.payload) {
        try { body = JSON.stringify(JSON.parse(m.payload), null, 2); } catch (_) {}
      }
      html += `<div><span class="badge info">${escapeHtml(m.direction)}</span> <small>${Number(m.bytes)} bytes</small><pre>${escapeHtml(body)}</pre></div>`;
    }
  }

  if (selectedSpanDetail.model_call) {
    const mc = selectedSpanDetail.model_call;
    const prefix = mc.cost_estimated ? '~' : '';
    html += `<h4>Model Call (${escapeHtml(mc.provider)} / ${escapeHtml(mc.model)})</h4>`;
    html += `<p>Tokens: ${Number(mc.input_tokens)} in (${Number(mc.cached_tokens)} cached) / ${Number(mc.output_tokens)} out | Cost: <strong>${prefix}$${Number(mc.cost_usd).toFixed(5)}</strong> <small>[${escapeHtml(priceTableDate)}]</small></p>`;
    if (mc.request_payload) {
      let reqBody = mc.request_payload;
      if (inspectorMode === 'pretty') {
        try { reqBody = JSON.stringify(JSON.parse(mc.request_payload), null, 2); } catch (_) {}
      }
      html += `<div><strong>Request Payload:</strong><pre>${escapeHtml(reqBody)}</pre></div>`;
    }
    if (mc.response_payload) {
      let respBody = mc.response_payload;
      if (inspectorMode === 'pretty') {
        try { respBody = JSON.stringify(JSON.parse(mc.response_payload), null, 2); } catch (_) {}
      }
      html += `<div><strong>Response Payload:</strong><pre>${escapeHtml(respBody)}</pre></div>`;
    }
  }

  document.getElementById('inspector-body').innerHTML = html;
  const anns = selectedSpanDetail.annotations || [];
  document.getElementById('inspector-annotations').innerHTML = anns.length
    ? anns.map(a => `<div style="font-size:12px; margin-bottom:4px;"><strong>${escapeHtml(a.author)}:</strong> ${escapeHtml(a.text)}</div>`).join('')
    : '<div style="color:var(--muted); font-size:12px;">No annotations yet.</div>';
}

async function submitAnnotation() {
  if (!selectedSpanDetail) return;
  const author = document.getElementById('ann-author').value || 'dev';
  const text = document.getElementById('ann-text').value;
  if (!text) return;
  await apiFetch(`/api/spans/${encodeURIComponent(selectedSpanDetail.span.id)}/annotations`, {
    method: 'POST',
    body: JSON.stringify({ author, text })
  });
  document.getElementById('ann-text').value = '';
  await inspectSpan(selectedSpanDetail.span.id);
}

async function runDiff() {
  const left = document.getElementById('diff-left').value;
  const right = document.getElementById('diff-right').value;
  if (!left || !right) return;
  const diff = await apiFetch(`/api/runs/diff?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`);
  document.getElementById('diff-view-card').style.display = 'block';
  document.getElementById('diff-summary').innerHTML = diff.first_divergence_index !== null
    ? `<span class="badge err">First Divergence at Step #${Number(diff.first_divergence_index)}</span> <strong>${escapeHtml(diff.first_divergence_reason || '')}</strong>`
    : `<span class="badge ok">Runs are structurally aligned with zero divergences.</span>`;
  document.getElementById('diff-entries').innerHTML = diff.entries.map(e => `
    <div class="diff-row ${e.diverged ? 'diverged' : ''}">
      <div>#${Number(e.step_index)}</div>
      <div>${e.left_span ? escapeHtml(e.left_span.name) + ' (' + escapeHtml(e.left_span.status) + ')' : '—'}</div>
      <div>
        ${e.right_span ? escapeHtml(e.right_span.name) + ' (' + escapeHtml(e.right_span.status) + ')' : '—'}
        ${e.diverged ? `<div style="color:#fca5a5;">↳ ${escapeHtml(e.divergence_reason || '')}</div>` : ''}
      </div>
    </div>
  `).join('');
}

async function loadServers() {
  const servers = await apiFetch('/api/servers');
  const el = document.getElementById('servers-list');
  if (!servers.length) {
    el.innerHTML = '<p style="color:var(--muted);">No MCP servers observed yet.</p>';
    return;
  }
  el.innerHTML = servers.map(s => {
    const depBadge = (s.deprecated_features_seen && s.deprecated_features_seen.length)
      ? `<span class="badge warn">deprecated feature in use: ${escapeHtml(s.deprecated_features_seen.join(', '))}</span>`
      : '';
    const changeBadge = s.schema_changes > 0
      ? `<span class="badge err">schema changed (${Number(s.schema_changes)})</span>`
      : '';
    return `
      <div class="run-item" data-server-id="${escapeHtml(s.id)}">
        <div style="display:flex; justify-content:space-between;">
          <strong>${escapeHtml(s.id)}</strong>
          <span class="badge info">${escapeHtml(s.transport)}</span>
        </div>
        <div style="font-size:12px; color:var(--muted); margin-top:4px;">
          ${Number(s.tool_count)} tools | eras: ${escapeHtml((s.protocol_versions_seen || []).join(', ') || 'auto')}
        </div>
        <div style="margin-top:4px;">${depBadge} ${changeBadge}</div>
      </div>
    `;
  }).join('');
}

async function selectServer(serverId) {
  selectedServerId = serverId;
  document.getElementById('catalog-server-title').textContent = `Server Tool Catalog: ${serverId}`;
  currentServerTools = await apiFetch(`/api/servers/${encodeURIComponent(serverId)}/tools`);
  const el = document.getElementById('tools-list');
  if (!currentServerTools.length) {
    el.innerHTML = '<p style="color:var(--muted);">No tools listed yet for this server.</p>';
    return;
  }
  el.innerHTML = currentServerTools.map((t, idx) => {
    const changedAlert = t.changed_count > 0
      ? `<div style="color:#fca5a5; margin-top:4px;"><strong>ALERT: Tool description/schema changed ${Number(t.changed_count)}x!</strong> Previous description: <code>${escapeHtml(t.previous_description || '')}</code></div>`
      : '';
    const poisonAlert = (t.poison_warnings && t.poison_warnings.length)
      ? `<div style="color:#fde68a; margin-top:4px;"><strong>Tool Poisoning Warning:</strong> ${escapeHtml(t.poison_warnings.join('; '))}</div>`
      : '';
    return `
      <div class="card" style="background:var(--bg); margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${escapeHtml(t.name)}</strong>
          <div>
            <span class="badge">sha256: ${escapeHtml(String(t.schema_hash || '').slice(0, 12))}</span>
            <button class="btn secondary" data-open-tool-idx="${Number(idx)}">Call Tool</button>
          </div>
        </div>
        <p style="margin:6px 0; color:var(--muted);">${escapeHtml(t.description)}</p>
        ${changedAlert}
        ${poisonAlert}
      </div>
    `;
  }).join('');
}

// F-10 & Testing §4: Schema form generator with safe fallback on pathological/recursive schemas
function isSchemaPathological(schema, depth = 0) {
  if (!schema || typeof schema !== 'object') return false;
  if (depth > 5) return true;
  if (schema.$ref) return true;
  if (Array.isArray(schema.oneOf) && schema.oneOf.length > 10) return true;
  if (Array.isArray(schema.anyOf) && schema.anyOf.length > 10) return true;
  if (Array.isArray(schema.enum) && schema.enum.length > 100) return true;
  if (schema.properties && typeof schema.properties === 'object') {
    const keys = Object.keys(schema.properties);
    if (keys.length > 40) return true;
    for (const k of keys) {
      if (isSchemaPathological(schema.properties[k], depth + 1)) return true;
    }
  }
  return false;
}

function openManualCall(idx) {
  const tool = currentServerTools[idx];
  if (!tool) return;
  const container = document.getElementById('manual-call-container');
  const schema = tool.input_schema || {};
  const fallback = isSchemaPathological(schema);

  if (fallback || !schema.properties) {
    container.innerHTML = `
      <p><span class="badge warn">Raw JSON Editor Mode</span> Tool: <strong>${escapeHtml(tool.name)}</strong></p>
      <textarea id="manual-raw-json" rows="6" style="width:100%; font-family:var(--font-mono);">{}</textarea>
      <div style="margin-top:8px;"><button class="btn" data-exec-tool="${escapeHtml(tool.name)}" data-exec-raw="true">Invoke ${escapeHtml(tool.name)}</button></div>
      <pre id="manual-call-output" style="display:none;"></pre>
    `;
  } else {
    const fields = Object.entries(schema.properties).map(([k, prop]) => `
      <div style="margin-bottom:6px;">
        <label style="display:block; font-size:12px;">${escapeHtml(k)} <small style="color:var(--muted);">(${escapeHtml(prop.type || 'any')})</small></label>
        <input class="manual-field" data-key="${escapeHtml(k)}" data-type="${escapeHtml(prop.type || 'string')}" style="width:100%;" />
      </div>
    `).join('');
    container.innerHTML = `
      <p>Tool: <strong>${escapeHtml(tool.name)}</strong></p>
      ${fields}
      <div style="margin-top:8px;"><button class="btn" data-exec-tool="${escapeHtml(tool.name)}" data-exec-raw="false">Invoke ${escapeHtml(tool.name)}</button></div>
      <pre id="manual-call-output" style="display:none;"></pre>
    `;
  }
}

async function executeManualCall(toolName, isRaw) {
  let args = {};
  if (isRaw) {
    try { args = JSON.parse(document.getElementById('manual-raw-json').value || '{}'); } catch (e) { alert('Invalid JSON'); return; }
  } else {
    document.querySelectorAll('.manual-field').forEach(inp => {
      const k = inp.getAttribute('data-key');
      const t = inp.getAttribute('data-type');
      const v = inp.value;
      if (v !== '') {
        if (t === 'number' || t === 'integer') args[k] = Number(v);
        else if (t === 'boolean') args[k] = (v === 'true');
        else args[k] = v;
      }
    });
  }
  const outEl = document.getElementById('manual-call-output');
  outEl.style.display = 'block';
  outEl.textContent = 'Calling tool...';
  try {
    const res = await apiFetch(`/api/servers/${encodeURIComponent(selectedServerId)}/call`, {
      method: 'POST',
      body: JSON.stringify({ tool_name: toolName, arguments: args })
    });
    outEl.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    outEl.textContent = 'Error: ' + e.message;
  }
}

async function loadRunXray(runId) {
  const calls = await apiFetch(`/api/runs/${encodeURIComponent(runId)}/xray`);
  const el = document.getElementById('xray-container');
  if (!calls.length) {
    el.innerHTML = '<p style="color:var(--muted);">No model calls recorded in this run.</p>';
    return;
  }
  el.innerHTML = calls.map((mc, i) => {
    const cb = mc.context_breakdown || {};
    const tot = Math.max(1, cb.total_tokens || 1);
    const pSys = ((cb.system_tokens || 0) / tot * 100).toFixed(1);
    const pTools = ((cb.tools_tokens || 0) / tot * 100).toFixed(1);
    const pUser = ((cb.user_tokens || 0) / tot * 100).toFixed(1);
    const pAsst = ((cb.assistant_tokens || 0) / tot * 100).toFixed(1);
    const pRes = ((cb.tool_results_tokens || 0) / tot * 100).toFixed(1);
    const warn = cb.bloat_warning
      ? `<div style="color:#fde68a; margin-top:6px;"><strong>⚠ ${escapeHtml(cb.bloat_warning)}</strong></div>`
      : '';
    return `
      <div class="card" style="background:var(--bg);">
        <div style="display:flex; justify-content:space-between;">
          <strong>Step #${i + 1}: ${escapeHtml(mc.model)}</strong>
          <span>Total Context: <strong>${Number(cb.total_tokens)} tokens</strong></span>
        </div>
        <div class="xray-bar">
          <div class="xray-seg-sys" style="width:${pSys}%" title="System (${pSys}%)"></div>
          <div class="xray-seg-tools" style="width:${pTools}%" title="Tools (${pTools}%)"></div>
          <div class="xray-seg-user" style="width:${pUser}%" title="User (${pUser}%)"></div>
          <div class="xray-seg-asst" style="width:${pAsst}%" title="Assistant (${pAsst}%)"></div>
          <div class="xray-seg-res" style="width:${pRes}%" title="Tool Results (${pRes}%)"></div>
        </div>
        <div style="font-size:12px; color:var(--muted); display:flex; gap:14px;">
          <span>🔵 System: ${Number(cb.system_tokens)} (${pSys}%)</span>
          <span>🟣 Tools: ${Number(cb.tools_tokens)} (${pTools}%)</span>
          <span>🟢 User: ${Number(cb.user_tokens)} (${pUser}%)</span>
          <span>🩵 Assistant: ${Number(cb.assistant_tokens)} (${pAsst}%)</span>
          <span>🟠 Tool Results: ${Number(cb.tool_results_tokens)} (${pRes}%)</span>
        </div>
        ${warn}
      </div>
    `;
  }).join('');
}

async function loadPolicies() {
  const pol = await apiFetch('/api/policies');
  document.getElementById('policy-enabled-toggle').checked = !!pol.enabled;
  document.getElementById('policy-rules-editor').value = JSON.stringify(pol.rules || [], null, 2);
  const decs = pol.recent_decisions || [];
  document.getElementById('policy-decisions-list').innerHTML = decs.length
    ? decs.map(d => `
        <div style="padding:6px 0; border-bottom:1px solid var(--border); font-size:12px;">
          <span class="badge ${d.verdict === 'deny' ? 'err' : 'ok'}">${escapeHtml(d.verdict)}</span>
          <strong>${escapeHtml(d.server_id)}:${escapeHtml(d.tool_name)}</strong>
          <span style="color:var(--muted);">(${escapeHtml(d.rule_id)} — ${escapeHtml(d.reason)})</span>
        </div>
      `).join('')
    : '<p style="color:var(--muted);">No policy decisions recorded yet.</p>';
}

async function savePolicies() {
  try {
    const enabled = document.getElementById('policy-enabled-toggle').checked;
    const rules = JSON.parse(document.getElementById('policy-rules-editor').value || '[]');
    await apiFetch('/api/policies', {
      method: 'POST',
      body: JSON.stringify({ enabled, rules })
    });
    await loadPolicies();
    await loadStatus();
  } catch (e) {
    alert('Failed to save policies: ' + e.message);
  }
}

async function runPolicyTest() {
  const server = document.getElementById('ptest-server').value;
  const tool = document.getElementById('ptest-tool').value;
  let argumentsVal = {};
  try { argumentsVal = JSON.parse(document.getElementById('ptest-args').value || '{}'); } catch (_) {}
  const res = await apiFetch('/api/policies/test', {
    method: 'POST',
    body: JSON.stringify({ server, tool, arguments: argumentsVal })
  });
  const el = document.getElementById('ptest-result');
  el.style.display = 'block';
  el.textContent = JSON.stringify(res, null, 2);
}

async function previewExport() {
  const format = document.getElementById('export-format').value;
  const run_ids = selectedRunId ? [selectedRunId] : [];
  const res = await apiFetch('/api/export', {
    method: 'POST',
    body: JSON.stringify({ run_ids, format, preview: true })
  });
  const box = document.getElementById('export-preview-box');
  box.style.display = 'block';
  box.textContent = `// Exact Redacted Export Preview (${res.bytes} bytes)\n` + res.content;
}

async function downloadExport() {
  const format = document.getElementById('export-format').value;
  const run_ids = selectedRunId ? [selectedRunId] : [];
  const res = await apiFetch('/api/export', {
    method: 'POST',
    body: JSON.stringify({ run_ids, format, preview: true })
  });
  const blob = new Blob([res.content], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `workbench-export.${format === 'jsonl' ? 'jsonl' : 'json'}`;
  a.click();
}

async function importJsonl() {
  const jsonl = document.getElementById('import-jsonl-box').value;
  if (!jsonl.trim()) return;
  const res = await apiFetch('/api/import', {
    method: 'POST',
    body: JSON.stringify({ jsonl })
  });
  document.getElementById('import-status').textContent = `Imported ${res.imported_runs} run(s)!`;
  await loadRuns();
}

async function refreshAll() {
  await Promise.all([loadStatus(), loadRuns(), loadServers(), loadPolicies()]);
}

// B5: Attach all event handlers via addEventListener and event delegation (no inline handlers)
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-refresh')?.addEventListener('click', () => refreshAll());

  document.getElementById('main-nav')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (btn) {
      switchTab(btn.getAttribute('data-tab'), btn);
    }
  });

  document.getElementById('run-status-filter')?.addEventListener('change', () => loadRuns());
  document.getElementById('btn-run-diff')?.addEventListener('click', () => runDiff());
  document.getElementById('btn-close-diff')?.addEventListener('click', () => {
    document.getElementById('diff-view-card').style.display = 'none';
  });

  document.getElementById('span-filter')?.addEventListener('input', () => renderSpans());
  document.getElementById('span-status-filter')?.addEventListener('change', () => renderSpans());

  document.getElementById('btn-inspector-pretty')?.addEventListener('click', () => setInspectorMode('pretty'));
  document.getElementById('btn-inspector-raw')?.addEventListener('click', () => setInspectorMode('raw'));
  document.getElementById('btn-submit-annotation')?.addEventListener('click', () => submitAnnotation());

  document.getElementById('btn-save-policies')?.addEventListener('click', () => savePolicies());
  document.getElementById('btn-run-policy-test')?.addEventListener('click', () => runPolicyTest());

  document.getElementById('btn-preview-export')?.addEventListener('click', () => previewExport());
  document.getElementById('btn-download-export')?.addEventListener('click', () => downloadExport());
  document.getElementById('btn-import-jsonl')?.addEventListener('click', () => importJsonl());

  document.getElementById('runs-list')?.addEventListener('click', (e) => {
    const item = e.target.closest('[data-run-id]');
    if (item) {
      selectRun(item.getAttribute('data-run-id'));
    }
  });

  document.getElementById('spans-container')?.addEventListener('click', (e) => {
    const row = e.target.closest('[data-span-id]');
    if (row) {
      inspectSpan(row.getAttribute('data-span-id'));
    }
  });

  document.getElementById('servers-list')?.addEventListener('click', (e) => {
    const item = e.target.closest('[data-server-id]');
    if (item) {
      selectServer(item.getAttribute('data-server-id'));
    }
  });

  document.getElementById('tools-list')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-open-tool-idx]');
    if (btn) {
      openManualCall(Number(btn.getAttribute('data-open-tool-idx')));
    }
  });

  document.getElementById('manual-call-container')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-exec-tool]');
    if (btn) {
      const toolName = btn.getAttribute('data-exec-tool');
      const isRaw = btn.getAttribute('data-exec-raw') === 'true';
      executeManualCall(toolName, isRaw);
    }
  });

  refreshAll();
});
"#;
