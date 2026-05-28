/* GAGMA Frontend — Main Application Logic v2.0 */

const API = '';
let currentAnalysisId = null;
let pollInterval = null;
let graphNetwork = null;
let currentThreatIntel = null;

// ── Init ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupUpload();
  setupTabs();
  setupChat();
  checkBackendStatus();
  loadStats();
  setupSandboxDrawer();
  loadBlocklistFeed();
  setupWebhookGateway();
  setupWhatsAppGateway();
  setInterval(loadStats, 10000);
  setInterval(loadBlocklistFeed, 12000);
});

// ── Stats Bar ──────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch(`${API}/api/analyses`);
    const list = await res.json();
    const completed = list.filter(a => a.status === 'COMPLETE');
    const critical = completed.filter(a => a.risk_level === 'CRITICAL' || a.risk_level === 'HIGH');
    const scores = completed.filter(a => a.risk_score != null).map(a => a.risk_score);
    const avg = scores.length ? Math.round(scores.reduce((s, v) => s + v, 0) / scores.length) : null;
    document.getElementById('stat-total').textContent = list.length;
    document.getElementById('stat-threats').textContent = completed.filter(a => a.risk_score >= 50).length;
    document.getElementById('stat-critical').textContent = critical.length;
    document.getElementById('stat-avg').textContent = avg != null ? avg + '/100' : '—';
  } catch (_) {}
}

// ── Demo Scenarios ─────────────────────────────────────
async function runDemo(scenario) {
  document.getElementById('progress-section').classList.remove('hidden');
  document.getElementById('progress-filename').textContent = 'Demo: ' + scenario;
  document.getElementById('progress-status').textContent = 'INITIALIZING';
  document.getElementById('results-section').classList.add('hidden');
  document.getElementById('progress-fill').style.width = '5%';

  // Animate steps while waiting
  const steps = ['DECOMPILING', 'EXTRACTING', 'BUILDING_GRAPH', 'ANALYZING', 'SCORING'];
  let stepIdx = 0;
  const stepTimer = setInterval(() => {
    if (stepIdx < steps.length) {
      updateProgress(steps[stepIdx]);
      stepIdx++;
    }
  }, 1800);

  try {
    const res = await fetch(`${API}/api/demo/${scenario}`, { method: 'POST' });
    clearInterval(stepTimer);
    const data = await res.json();
    if (data.error) { document.getElementById('progress-status').textContent = data.error; return; }
    currentAnalysisId = data.analysis_id;
    const full = await fetch(`${API}/api/status/${data.analysis_id}`);
    const fullData = await full.json();
    updateProgress('COMPLETE');
    showResults(fullData);
    loadStats();
  } catch (err) {
    clearInterval(stepTimer);
    document.getElementById('progress-status').textContent = 'Demo failed: ' + err.message;
  }
}
window.runDemo = runDemo;

// ── Backend Status ─────────────────────────────────────
async function checkBackendStatus() {
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('status-label');
  try {
    const res = await fetch(`${API}/`);
    if (res.ok) {
      dot.className = 'status-dot online';
      label.textContent = 'System Online';
    }
  } catch {
    dot.className = 'status-dot offline';
    label.textContent = 'Offline';
  }
}

// ── Upload ─────────────────────────────────────────────
function setupUpload() {
  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('file-input');
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });
}

async function handleFile(file) {
  if (!file.name.toLowerCase().endsWith('.apk')) {
    alert('Please upload an APK file'); return;
  }
  document.getElementById('progress-section').classList.remove('hidden');
  document.getElementById('progress-filename').textContent = file.name;
  document.getElementById('progress-status').textContent = 'Uploading';
  document.getElementById('results-section').classList.add('hidden');

  const fd = new FormData();
  fd.append('file', file);
  try {
    const res = await fetch(`${API}/api/analyze`, { method: 'POST', body: fd });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    currentAnalysisId = data.analysis_id;
    startPolling();
  } catch (err) {
    document.getElementById('progress-status').textContent = 'Upload failed';
  }
}

// ── Polling ────────────────────────────────────────────
function startPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(checkStatus, 1500);
  checkStatus();
}

async function checkStatus() {
  if (!currentAnalysisId) return;
  try {
    const res = await fetch(`${API}/api/status/${currentAnalysisId}`);
    const data = await res.json();
    updateProgress(data.status);
    if (data.status === 'COMPLETE') {
      clearInterval(pollInterval);
      showResults(data);
      loadStats();
    } else if (data.status === 'FAILED') {
      clearInterval(pollInterval);
      document.getElementById('progress-status').textContent = 'Analysis Failed';
    }
  } catch (_) {}
}

function updateProgress(status) {
  const steps = ['DECOMPILING', 'EXTRACTING', 'BUILDING_GRAPH', 'ANALYZING', 'SCORING', 'COMPLETE'];
  const idx = steps.indexOf(status);
  const pct = idx >= 0 ? Math.round(((idx + 1) / steps.length) * 100) : 5;
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-status').textContent = status.replace(/_/g, ' ');
  document.querySelectorAll('.step').forEach(s => {
    const si = steps.indexOf(s.dataset.step);
    s.classList.remove('active', 'done');
    if (si < idx) s.classList.add('done');
    else if (si === idx) s.classList.add('active');
  });
}

// ── Results ────────────────────────────────────────────
function showResults(data) {
  document.getElementById('results-section').classList.remove('hidden');
  document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });
  if (data.risk_score) renderRiskScore(data.risk_score);
  if (data.static_analysis) renderAPKInfo(data.static_analysis);
  if (data.banking_flags && data.banking_flags.length) renderBankingFlags(data.banking_flags);
  if (data.kill_chain && data.kill_chain.length) renderKillChain(data.kill_chain);
  if (data.behavioral_findings) renderFindings(data.behavioral_findings);
  if (data.graph_data) renderGraph(data.graph_data);
  if (data.threat_intel) { currentThreatIntel = data.threat_intel; renderIntelTab(data.threat_intel, data.banking_flags || []); }
  if (data.dynamic_analysis) renderDynamic(data.dynamic_analysis);
  loadReport();
  
  // Trigger Virtual CSO Smartphone push alert for High/Critical risk profiles
  if (data.risk_score && data.risk_score.total_score >= 50 && data.static_analysis) {
    const pkg = data.static_analysis.metadata.package_name;
    const score = data.risk_score.total_score;
    const lvl = data.risk_score.risk_level;
    triggerPhoneAlert(pkg, score, lvl);
  }
}

function renderDynamic(dyn) {
  const el = document.getElementById('dynamic-content');
  if (!dyn || !dyn.runtime_behaviors || !dyn.runtime_behaviors.length) {
    el.innerHTML = '<p class="loading-text">No dynamic analysis findings.</p>';
    return;
  }
  const verdictColors = { MALICIOUS: 'var(--red)', SUSPICIOUS: 'var(--orange)', CLEAN: 'var(--green)' };
  const vc = verdictColors[dyn.sandbox_verdict] || 'var(--text-2)';
  let html = `
    <div class="card" style="margin-bottom:1rem;border-left:3px solid ${vc}">
      <div class="card-label">Sandbox Emulation Verdict</div>
      <div style="font-size:1.4rem;font-weight:800;font-family:var(--mono);color:${vc}">${esc(dyn.sandbox_verdict)}</div>
      <div style="font-size:.78rem;color:var(--text-2);margin-top:.3rem">${esc(dyn.verdict_detail)}</div>
      <div style="font-size:.65rem;color:var(--text-3);margin-top:.5rem">${esc(dyn.analysis_method)}</div>
    </div>`;
  html += '<div class="card-label" style="margin-bottom:.75rem">Predicted Runtime Behaviors</div>';
  for (const b of dyn.runtime_behaviors) {
    const sevColors = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)' };
    const sc = sevColors[b.severity] || 'var(--text-2)';
    html += `
      <div class="finding-item ${b.severity}" style="margin-bottom:.65rem">
        <div class="finding-head">
          <span class="finding-name">${esc(b.title)}</span>
          <span class="sev-badge ${b.severity}">${b.severity.toUpperCase()}</span>
        </div>
        <div class="finding-desc">${esc(b.detail)}</div>
        ${b.data_flow ? `<div style="font-size:.68rem;font-family:var(--mono);color:var(--accent);margin-top:.3rem">${esc(b.data_flow)}</div>` : ''}
        ${b.network_indicator ? `<div style="font-size:.68rem;color:var(--text-3);margin-top:.2rem">Network: ${esc(b.network_indicator)}</div>` : ''}
      </div>`;
  }
  el.innerHTML = html;
}

async function blockAPK() {
  if (!currentAnalysisId) return;
  try {
    const res = await fetch(API + '/api/prevent/auto-block/' + currentAnalysisId, { method: 'POST' });
    const data = await res.json();
    if (data.status === 'blocked') {
      alert('APK added to enterprise blocklist. Total blocked: ' + data.total_blocked);
    } else {
      alert(data.detail || 'Could not block APK.');
    }
  } catch (err) { alert('Block failed: ' + err.message); }
}
window.blockAPK = blockAPK;

function renderRiskScore(score) {
  const num = document.getElementById('risk-number');
  animateNumber('risk-number', 0, Math.round(score.total_score), 1200);
  const lvl = score.risk_level;
  num.className = 'risk-number ' + lvl.toLowerCase();
  const badge = document.getElementById('risk-badge');
  badge.textContent = lvl;
  badge.className = 'risk-badge ' + lvl;

  const items = [
    { label: 'Permissions', value: score.permissions_score, max: 25, color: '#ef4444' },
    { label: 'Suspicious APIs', value: score.api_calls_score, max: 25, color: '#f97316' },
    { label: 'Behavioral', value: score.behavioral_score, max: 30, color: '#6366f1' },
    { label: 'Threat Intel', value: score.threat_intel_score, max: 20, color: '#3b82f6' },
  ];
  document.getElementById('risk-bars').innerHTML = items.map(it => `
    <div class="risk-bar-row">
      <span class="label">${it.label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${it.color}" data-target="${(it.value/it.max)*100}"></div></div>
      <span class="val">${it.value}/${it.max}</span>
    </div>
  `).join('');
  setTimeout(() => {
    document.querySelectorAll('.bar-fill').forEach(el => {
      el.style.width = el.dataset.target + '%';
    });
  }, 100);
}

function renderAPKInfo(sa) {
  const m = sa.metadata;
  const rows = [
    ['Package', m.package_name],
    ['Version', `${m.version_name} (${m.version_code})`],
    ['Min SDK', `API ${m.min_sdk}`],
    ['Target SDK', `API ${m.target_sdk}`],
    ['File Size', formatBytes(m.file_size)],
    ['SHA-256', m.sha256 ? m.sha256.substring(0, 18) + '…' : 'N/A'],
    ['Permissions', `${sa.permissions.length} total (${sa.permissions.filter(p => p.is_suspicious).length} dangerous)`],
    ['Suspicious APIs', sa.suspicious_api_calls.length],
    ['Components', `${sa.activities.length}A / ${sa.services.length}S / ${sa.receivers.length}R`],
    ['Classes', sa.classes_count.toLocaleString()],
  ];
  document.getElementById('apk-info').innerHTML = rows.map(([l, v]) =>
    `<div class="info-row"><span class="lbl">${l}</span><span class="val">${esc(String(v))}</span></div>`
  ).join('');
}

function renderBankingFlags(flags) {
  const sec = document.getElementById('banking-flags-section');
  const list = document.getElementById('banking-flags-list');
  sec.classList.remove('hidden');
  list.innerHTML = flags.map(f => `
    <div class="flag-item ${f.severity}">
      <div class="flag-header">
        <span class="flag-title">${esc(f.title)}</span>
        <span class="flag-type">${esc(f.flag_type)}</span>
      </div>
      <div class="flag-detail">${esc(f.detail)}</div>
      ${f.affected_apps && f.affected_apps.length ? `<div class="flag-apps">Targeted: ${f.affected_apps.join(' · ')}</div>` : ''}
    </div>
  `).join('');
}

function renderKillChain(steps) {
  const sec = document.getElementById('kill-chain-section');
  const tl = document.getElementById('kc-timeline');
  sec.classList.remove('hidden');
  let html = '';
  steps.forEach((s, i) => {
    if (i > 0) html += '<div class="kc-connector"></div>';
    html += `
      <div class="kc-step">
        <div class="kc-node">${s.stage}</div>
        <div class="kc-name">${esc(s.name)}</div>
        <div class="kc-technique">${esc(s.technique)}</div>
        <div class="kc-desc">${esc(s.description.substring(0, 70))}${s.description.length > 70 ? '…' : ''}</div>
      </div>`;
  });
  tl.innerHTML = html;
}

function renderFindings(findings) {
  const list = document.getElementById('findings-list');
  if (!findings.length) {
    list.innerHTML = '<p class="loading-text">No malicious behavioral patterns detected.</p>'; return;
  }
  list.innerHTML = findings.map(f => {
    const mitreTags = [...(f.mitre_techniques || []), ...(f.mitre_tactics || [])]
      .map(t => {
        const id = t.split(' ')[0];
        return `<span class="mitre-tag">${esc(id)}</span>`;
      }).join('');
    return `
      <div class="finding-item ${f.severity}">
        <div class="finding-head">
          <span class="finding-name">${esc(f.pattern_name)}</span>
          <span class="sev-badge ${f.severity}">${f.severity.toUpperCase()}</span>
        </div>
        <div class="finding-desc">${esc(f.description)}</div>
        ${mitreTags ? `<div class="mitre-tags">${mitreTags}</div>` : ''}
        ${f.evidence && f.evidence.length ? `<div class="finding-evidence">${f.evidence.slice(0, 4).map(e => esc(e)).join(' · ')}</div>` : ''}
      </div>`;
  }).join('');
}

function renderIntelTab(intel, bankingFlags) {
  const el = document.getElementById('intel-content');
  let html = '';
  const vt = intel && intel.virustotal;
  if (vt && vt.found) {
    const rate = vt.malicious || 0;
    const total = vt.total_engines || 76;
    const pct = Math.round((rate / total) * 100);
    html += `
      <div class="intel-grid">
        <div class="intel-card">
          <div class="intel-card-label">Detection Rate</div>
          <div class="intel-value">${vt.detection_rate || `${rate}/${total}`}</div>
          <div class="intel-sub">across ${total} AV engines</div>
          <div class="detect-bar">
            <div style="font-size:.68rem;color:var(--text-3)">Malicious engines</div>
            <div class="detect-track"><div class="detect-fill" style="width:${pct}%"></div></div>
          </div>
        </div>
        <div class="intel-card">
          <div class="intel-card-label">Threat Family</div>
          <div class="intel-value" style="font-size:1.1rem;word-break:break-word">${esc(vt.popular_threat_name || 'Unknown')}</div>
          <div class="intel-sub">${(vt.tags || []).join(' · ')}</div>
        </div>
      </div>
      <div class="card" style="margin-bottom:1rem">
        <div class="card-label">VirusTotal Report</div>
        <a href="${esc(vt.link || '')}" target="_blank" rel="noopener" style="font-size:.78rem;color:var(--accent)">View full VirusTotal analysis →</a>
      </div>`;
  } else {
    html += `<div class="card" style="margin-bottom:1rem"><div class="card-label">VirusTotal</div><p style="font-size:.82rem;color:var(--text-2)">Sample not found in VirusTotal database — this may be a new or private sample.</p></div>`;
  }
  if (bankingFlags && bankingFlags.length) {
    html += `<div class="card-label" style="margin-bottom:.75rem">Banking Threat Indicators</div>`;
    html += bankingFlags.map(f => `
      <div class="flag-item ${f.severity}" style="margin-bottom:.65rem">
        <div class="flag-header"><span class="flag-title">${esc(f.title)}</span><span class="flag-type">${esc(f.flag_type)}</span></div>
        <div class="flag-detail">${esc(f.detail)}</div>
      </div>`).join('');
  }
  
  // Add YARA Signature Rule Card
  html += `
    <div class="card" style="margin-top:1.5rem;border-top:2px solid var(--orange)">
      <div class="card-label" style="color:var(--orange)">Incident Response — Automated YARA Signature</div>
      <p style="font-size:0.8rem;color:var(--text-2);margin-bottom:0.75rem">Deployable search signature generated instantly based on dangerous accessibility permissions, suspect packages, and network indicators.</p>
      <pre id="yara-codeblock" style="font-family:var(--mono);font-size:0.72rem;color:var(--accent);background:rgba(2,4,8,0.6);border:1px solid var(--border);border-radius:4px;padding:1rem;overflow-x:auto;margin-top:0.5rem;max-height:280px">Generating custom YARA rule...</pre>
      <button class="btn btn-primary btn-sm" style="margin-top:0.75rem;border-color:rgba(255,159,10,0.3);color:var(--orange);background:rgba(255,159,10,0.06)" onclick="downloadYaraRule()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download YARA Rule (.yar)
      </button>
    </div>`;

  el.innerHTML = html || '<p class="loading-text">No threat intelligence available.</p>';
  
  // Fetch YARA rule asynchronously
  setTimeout(loadYaraRule, 50);
}

// ── YARA Rules Service ──────────────────────────────────
async function loadYaraRule() {
  const codeblock = document.getElementById('yara-codeblock');
  if (!codeblock || !currentAnalysisId) return;
  try {
    const res = await fetch(`${API}/api/status/${currentAnalysisId}/yara`);
    if (res.ok) {
      const text = await res.text();
      codeblock.textContent = text;
      window.currentYaraText = text;
    } else {
      codeblock.textContent = "Failed to generate YARA signature rule.";
    }
  } catch (err) {
    codeblock.textContent = "Error loading YARA rule: " + err.message;
  }
}
window.loadYaraRule = loadYaraRule;

function downloadYaraRule() {
  if (!window.currentYaraText) {
    alert("YARA rule not ready yet.");
    return;
  }
  const blob = new Blob([window.currentYaraText], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `gagma_threat_${currentAnalysisId}.yar`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
window.downloadYaraRule = downloadYaraRule;

// ── Graph ──────────────────────────────────────────────
function renderGraph(gd) {
  const container = document.getElementById('graph-container');
  if (!gd || !gd.nodes || !gd.nodes.length) {
    container.innerHTML = '<p class="loading-text" style="padding-top:200px">No graph data available</p>'; return;
  }
  const colors = {
    apk: { background: '#3b82f6', border: '#2563eb', font: { color: '#fff' } },
    permission_dangerous: { background: '#ef4444', border: '#dc2626', font: { color: '#fff' } },
    permission_normal: { background: '#22c55e', border: '#16a34a', font: { color: '#000' } },
    api_critical: { background: '#dc2626', border: '#b91c1c', font: { color: '#fff' } },
    api_high: { background: '#f97316', border: '#ea580c', font: { color: '#000' } },
    api_medium: { background: '#eab308', border: '#ca8a04', font: { color: '#000' } },
    api_low: { background: '#22c55e', border: '#16a34a', font: { color: '#000' } },
    url: { background: '#eab308', border: '#ca8a04', font: { color: '#000' } },
    ip: { background: '#f59e0b', border: '#d97706', font: { color: '#000' } },
  };
  const nodes = new vis.DataSet(gd.nodes.map(n => ({
    ...n, shape: n.group === 'apk' ? 'diamond' : 'dot',
    color: colors[n.group] || { background: '#4a5568', border: '#374151' },
    font: { color: '#dce3f0', size: n.group === 'apk' ? 13 : 10, face: 'Inter' },
    shadow: { enabled: true, color: 'rgba(0,0,0,.4)', size: 8 },
  })));
  const edges = new vis.DataSet(gd.edges.map(e => ({
    ...e, arrows: 'to',
    font: { color: '#4a5568', size: 8, face: 'Inter', strokeWidth: 0 },
    smooth: { type: 'curvedCW', roundness: 0.2 }, width: 1.5, color: { color: '#1e293b' },
  })));
  const opts = {
    physics: { forceAtlas2Based: { gravitationalConstant: -40, centralGravity: 0.005, springLength: 120 }, solver: 'forceAtlas2Based', stabilization: { iterations: 100 } },
    interaction: { hover: true, tooltipDelay: 100 },
    nodes: { borderWidth: 2, borderWidthSelected: 3 },
    background: { color: 'transparent' },
  };
  graphNetwork = new vis.Network(container, { nodes, edges }, opts);
  document.getElementById('btn-fit-graph').onclick = () => graphNetwork.fit({ animation: { duration: 400 } });
}

// ── Tabs ───────────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-content-' + btn.dataset.tab).classList.add('active');
      if (btn.dataset.tab === 'graph' && graphNetwork) graphNetwork.fit({ animation: { duration: 300 } });
      if (btn.dataset.tab === 'campaign') {
        loadCampaignGraph();
      }
    });
  });
}

let campaignNetwork = null;
async function loadCampaignGraph() {
  const container = document.getElementById('campaign-graph-container');
  const loading = document.getElementById('campaign-loading');
  if (!container) return;
  
  if (loading) {
    loading.style.display = 'block';
    loading.textContent = 'Loading campaign clusters...';
  }
  
  try {
    const res = await fetch(`${API}/api/graph/campaign-clustering`);
    const gd = await res.json();
    
    if (loading) loading.style.display = 'none';
    
    if (!gd || !gd.nodes || !gd.nodes.length) {
      container.innerHTML = '<p class="loading-text" style="padding-top:200px">No active campaign cluster data available. Scan multiple banking APKs to view clusters.</p>';
      return;
    }
    
    const colors = {
      apk: { background: '#00f0ff', border: '#00c8ff', font: { color: '#fff' } },
      permission_dangerous: { background: '#ef4444', border: '#dc2626', font: { color: '#fff' } },
      permission_normal: { background: '#22c55e', border: '#16a34a', font: { color: '#000' } },
      api_critical: { background: '#dc2626', border: '#b91c1c', font: { color: '#fff' } },
      api_high: { background: '#f97316', border: '#ea580c', font: { color: '#000' } },
      api_medium: { background: '#eab308', border: '#ca8a04', font: { color: '#000' } },
      api_low: { background: '#22c55e', border: '#16a34a', font: { color: '#000' } },
      url: { background: '#eab308', border: '#ca8a04', font: { color: '#000' } },
      ip: { background: '#f59e0b', border: '#d97706', font: { color: '#000' } },
    };
    
    const nodes = new vis.DataSet(gd.nodes.map(n => ({
      ...n,
      shape: n.group === 'apk' ? 'diamond' : 'dot',
      color: colors[n.group] || { background: '#4a5568', border: '#374151' },
      font: { color: '#dce3f0', size: n.group === 'apk' ? 12 : 9, face: 'Inter' },
      shadow: { enabled: true, color: 'rgba(0,0,0,.4)', size: 8 },
    })));
    
    const edges = new vis.DataSet(gd.edges.map(e => ({
      ...e,
      arrows: 'to',
      font: { color: '#4a5568', size: 8, face: 'Inter', strokeWidth: 0 },
      smooth: { type: 'curvedCW', roundness: 0.2 },
      width: 1.5,
      color: { color: '#1e293b' },
    })));
    
    const opts = {
      physics: {
        forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 150 },
        solver: 'forceAtlas2Based',
        stabilization: { iterations: 120 }
      },
      interaction: { hover: true, tooltipDelay: 100 },
      nodes: { borderWidth: 2, borderWidthSelected: 3 },
      background: { color: 'transparent' },
    };
    
    campaignNetwork = new vis.Network(container, { nodes, edges }, opts);
    document.getElementById('btn-fit-campaign').onclick = () => campaignNetwork.fit({ animation: { duration: 400 } });
  } catch (err) {
    if (loading) loading.style.display = 'none';
    container.innerHTML = `<p class="loading-text" style="padding-top:200px;color:var(--red)">Failed to load campaign clusters: ${err.message}</p>`;
  }
}
window.loadCampaignGraph = loadCampaignGraph;

// ── Chat ───────────────────────────────────────────────
function setupChat() {
  document.getElementById('chat-send').addEventListener('click', sendChat);
  document.getElementById('chat-input').addEventListener('keypress', e => { if (e.key === 'Enter') sendChat(); });
}

window.sendSuggestion = (text) => {
  document.getElementById('chat-input').value = text;
  sendChat();
};

async function sendChat() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg || !currentAnalysisId) return;
  input.value = '';
  addMsg(msg, 'user');
  const tid = addMsg('Analyzing…', 'bot', true);
  try {
    const res = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_id: currentAnalysisId, message: msg }),
    });
    const data = await res.json();
    removeMsg(tid);
    addMsg(data.response || 'No response received.', 'bot', false, true);
  } catch (err) {
    removeMsg(tid);
    addMsg('Connection error. Please try again.', 'bot');
  }
}

function addMsg(text, type, isLoading = false, isMarkdown = false) {
  const container = document.getElementById('chat-msgs');
  const id = 'msg-' + Date.now();
  const div = document.createElement('div');
  div.id = id;
  div.className = `chat-msg ${type}`;
  const av = type === 'bot' ? '<div class="chat-av bot">GA</div>' : '<div class="chat-av user">A</div>';
  const content = isLoading
    ? `<p style="color:var(--text-3)">Analyzing…</p>`
    : isMarkdown
      ? marked.parse(text)
      : `<p>${esc(text)}</p>`;
  div.innerHTML = `${av}<div class="chat-bubble">${content}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeMsg(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// ── Report ─────────────────────────────────────────────
async function loadReport() {
  if (!currentAnalysisId) return;
  try {
    const res = await fetch(`${API}/api/report/${currentAnalysisId}`);
    const data = await res.json();
    document.getElementById('report-content').innerHTML = marked.parse(data.report || 'Report not available.');
  } catch {
    document.getElementById('report-content').innerHTML = '<p class="loading-text">Report unavailable.</p>';
  }
  document.getElementById('btn-download-report').onclick = async () => {
    try {
      const res = await fetch(`${API}/api/report/${currentAnalysisId}`);
      const data = await res.json();
      const blob = new Blob([data.report], { type: 'text/markdown' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `GAGMA_Report_${currentAnalysisId}.md`;
      a.click();
    } catch { alert('Failed to download report.'); }
  };
  document.getElementById('btn-print-report').onclick = () => window.print();
}

// ── Sandbox & Threat Feed Overlays ──────────────────────
function setupSandboxDrawer() {
  const toggle = document.getElementById('btn-toggle-sandbox');
  const close = document.getElementById('btn-close-sandbox');
  const drawer = document.getElementById('sandbox-drawer');
  
  if (toggle && drawer) {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      drawer.classList.toggle('open');
    });
  }
  if (close && drawer) {
    close.addEventListener('click', () => {
      drawer.classList.remove('open');
    });
  }
  document.addEventListener('click', (e) => {
    if (drawer && drawer.classList.contains('open') && !drawer.contains(e.target)) {
      drawer.classList.remove('open');
    }
  });
}

async function loadBlocklistFeed() {
  const container = document.getElementById('hud-blocklist-feed');
  if (!container) return;
  try {
    const res = await fetch(`${API}/api/prevent/stats`);
    const stats = await res.json();
    
    const res2 = await fetch(`${API}/api/analyses`);
    const list = await res2.json();
    const blocked = list.filter(a => a.risk_score >= 80).slice(0, 3);
    
    if (blocked.length === 0 && stats.total_blocked === 0) {
      container.innerHTML = `
        <div class="hud-empty">
          <p>No active incidents registered in database. Use the Simulation Sandbox console in the header to run threat simulations.</p>
        </div>`;
      return;
    }
    
    let html = '';
    blocked.forEach(a => {
      const timeStr = new Date(a.created_at || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      html += `
        <div class="hud-item" style="border-left: 2px solid var(--red);">
          <span class="hud-badge blocked">Blocked</span>
          <div class="hud-info">
            <h4 style="font-family:var(--mono);font-size:0.75rem;color:var(--red);">${a.apk_hash.substring(0, 16)}...</h4>
            <p>${a.apk_name || 'APK Payload'} &nbsp;·&nbsp; Risk Score: <strong>${a.risk_score}</strong> &nbsp;·&nbsp; ${timeStr}</p>
          </div>
        </div>`;
    });
    
    if (html === '') {
      html += `
        <div class="hud-item">
          <span class="hud-badge compl" style="background:rgba(0, 240, 255, 0.05);color:var(--accent)">Idle</span>
          <div class="hud-info">
            <h4>Gateway Ready</h4>
            <p>Active signature auditing and blocking operational on port 80/443.</p>
          </div>
        </div>`;
    }
    container.innerHTML = html;
  } catch (_) {
    container.innerHTML = `
      <div class="hud-empty">
        <p>Telemetry system connecting to threat intelligence database...</p>
      </div>`;
  }
}

// ── SIEM / MDM Webhook Config Gateway ────────────────────
async function setupWebhookGateway() {
  const input = document.getElementById('webhook-url-input');
  const btnSave = document.getElementById('btn-save-webhook');
  const btnTest = document.getElementById('btn-test-webhook');
  const statusMsg = document.getElementById('webhook-status-msg');
  
  if (!input || !btnSave || !btnTest || !statusMsg) return;

  // Load existing configuration
  try {
    const res = await fetch(`${API}/api/webhooks/config`);
    const data = await res.json();
    if (data.url) {
      input.value = data.url;
      statusMsg.innerHTML = `Linked Gateway: <strong style="color:var(--green)">ACTIVE</strong> &nbsp;·&nbsp; <span style="color:var(--text-2)">Monitoring real-time telemetry stream.</span>`;
    }
  } catch (_) {}

  // Save Config
  btnSave.addEventListener('click', async () => {
    const url = input.value.trim();
    if (!url) {
      statusMsg.innerHTML = `<span style="color:var(--red)">Error: Webhook URL cannot be empty.</span>`;
      return;
    }
    statusMsg.innerHTML = `<span style="color:var(--orange)">Linking secure threat gateway...</span>`;
    try {
      const res = await fetch(`${API}/api/webhooks/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (res.ok) {
        statusMsg.innerHTML = `Linked Gateway: <strong style="color:var(--green)">ACTIVE</strong> &nbsp;·&nbsp; <span style="color:var(--text-2)">Threat webhook registered in secure database.</span>`;
      } else {
        statusMsg.innerHTML = `<span style="color:var(--red)">Failed to link gateway. Verify API availability.</span>`;
      }
    } catch (err) {
      statusMsg.innerHTML = `<span style="color:var(--red)">Error linking gateway: ${err.message}</span>`;
    }
  });

  // Test Config
  btnTest.addEventListener('click', async () => {
    const url = input.value.trim();
    if (!url) {
      statusMsg.innerHTML = `<span style="color:var(--red)">Error: Enter a URL before dispatching test.</span>`;
      return;
    }
    statusMsg.innerHTML = `<span style="color:var(--orange)">Dispatching mock incident threat payload to SIEM receiver...</span>`;
    try {
      const res = await fetch(`${API}/api/webhooks/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (res.ok) {
        statusMsg.innerHTML = `Test Status: <strong style="color:var(--green)">SUCCESS (200 OK)</strong> &nbsp;·&nbsp; <span style="color:var(--text-2)">SIEM/MDM successfully acknowledged mock incident payload!</span>`;
      } else {
        statusMsg.innerHTML = `Test Status: <strong style="color:var(--red)">FAILED</strong> &nbsp;·&nbsp; <span style="color:var(--red)">${data.detail || 'Service returned an error.'}</span>`;
      }
    } catch (err) {
      statusMsg.innerHTML = `Test Status: <strong style="color:var(--red)">UNREACHABLE</strong> &nbsp;·&nbsp; <span style="color:var(--red)">${err.message}</span>`;
    }
  });
}

// ── Utilities ──────────────────────────────────────────
function animateNumber(id, start, end, dur) {
  const el = document.getElementById(id);
  const t0 = performance.now();
  function tick(t) {
    const p = Math.min((t - t0) / dur, 1);
    el.textContent = Math.round(start + (end - start) * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

// ── WhatsApp Bot Alert Gateway ───────────────────────────
async function setupWhatsAppGateway() {
  const checkEnabled = document.getElementById('wa-enabled');
  const inputPhone = document.getElementById('wa-phone');
  const inputApiKey = document.getElementById('wa-apikey');
  const btnSave = document.getElementById('btn-save-wa');
  const btnTest = document.getElementById('btn-test-wa');
  const statusMsg = document.getElementById('wa-status-msg');

  if (!checkEnabled || !inputPhone || !inputApiKey || !btnSave || !btnTest || !statusMsg) return;

  // Update Virtual phone lockscreen time dynamically
  updateVirtualPhoneClock();
  setInterval(updateVirtualPhoneClock, 30000);

  // Load existing config
  try {
    const res = await fetch(`${API}/api/webhooks/whatsapp`);
    const config = await res.json();
    checkEnabled.checked = config.enabled;
    inputPhone.value = config.phone || '';
    inputApiKey.value = config.apikey || '';
    if (config.enabled && config.phone) {
      statusMsg.innerHTML = `Active Alerting: <strong style="color:#00ff66">ENABLED</strong> &nbsp;·&nbsp; <span style="color:var(--text-2)">Broadcasting threats to ${esc(config.phone)}</span>`;
    }
  } catch (_) {}

  // Save Settings
  btnSave.addEventListener('click', async () => {
    const enabled = checkEnabled.checked;
    const phone = inputPhone.value.trim();
    const apikey = inputApiKey.value.trim();

    if (enabled && (!phone || !apikey)) {
      statusMsg.innerHTML = `<span style="color:var(--red)">Error: Phone number and API Key are required to enable alerts.</span>`;
      return;
    }

    statusMsg.innerHTML = `<span style="color:var(--orange)">Updating alert registry...</span>`;
    try {
      const res = await fetch(`${API}/api/webhooks/whatsapp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, phone, apikey })
      });
      if (res.ok) {
        statusMsg.innerHTML = `Active Alerting: <strong style="color:#00ff66">${enabled ? 'ENABLED' : 'DISABLED'}</strong> &nbsp;·&nbsp; <span style="color:var(--text-2)">Configuration successfully locked to SQLite.</span>`;
      } else {
        statusMsg.innerHTML = `<span style="color:var(--red)">Failed to save configuration.</span>`;
      }
    } catch (err) {
      statusMsg.innerHTML = `<span style="color:var(--red)">Connection Error: ${err.message}</span>`;
    }
  });

  // Test Alerts
  btnTest.addEventListener('click', async () => {
    const phone = inputPhone.value.trim();
    const apikey = inputApiKey.value.trim();
    if (!phone || !apikey) {
      statusMsg.innerHTML = `<span style="color:var(--red)">Error: Input target phone and API key to send test message.</span>`;
      return;
    }
    statusMsg.innerHTML = `<span style="color:var(--orange)">Broadcasting instant WhatsApp test payload...</span>`;
    try {
      const res = await fetch(`${API}/api/webhooks/whatsapp/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true, phone, apikey })
      });
      const data = await res.json();
      if (res.ok) {
        statusMsg.innerHTML = `Test Dispatch: <strong style="color:#00ff66">SUCCESS</strong> &nbsp;·&nbsp; <span style="color:var(--text-2)">Check your phone! Message sent.</span>`;
      } else {
        statusMsg.innerHTML = `Test Dispatch: <strong style="color:var(--red)">FAILED</strong> &nbsp;·&nbsp; <span style="color:var(--red)">${data.detail || 'Service connection error.'}</span>`;
      }
    } catch (err) {
      statusMsg.innerHTML = `Test Dispatch: <strong style="color:var(--red)">ERROR</strong> &nbsp;·&nbsp; <span style="color:var(--red)">${err.message}</span>`;
    }
  });

  // Setup virtual smartphone lockscreen tap & home buttons
  const homeBtn = document.getElementById('phone-home-btn');
  const notifBanner = document.getElementById('phone-notification');

  if (homeBtn) {
    homeBtn.addEventListener('click', () => {
      resetVirtualPhone();
    });
  }

  if (notifBanner) {
    notifBanner.addEventListener('click', () => {
      openVirtualWhatsApp();
    });
  }
}

function updateVirtualPhoneClock() {
  const clockText = document.getElementById('lockscreen-clock-text');
  const timeBarText = document.getElementById('phone-current-time');
  const dateText = document.getElementById('lockscreen-date-text');

  const now = new Date();
  const hrs = String(now.getHours()).padStart(2, '0');
  const mins = String(now.getMinutes()).padStart(2, '0');
  const clockStr = `${hrs}:${mins}`;

  if (clockText) clockText.textContent = clockStr;
  if (timeBarText) timeBarText.textContent = clockStr;

  if (dateText) {
    const options = { weekday: 'long', month: 'short', day: 'numeric' };
    dateText.textContent = now.toLocaleDateString('en-US', options);
  }
}

let activeAlertPkg = '';
let activeAlertScore = 0;

function triggerPhoneAlert(pkgName, score, level) {
  activeAlertPkg = pkgName;
  activeAlertScore = score;

  const phone = document.getElementById('virtual-phone');
  const notif = document.getElementById('phone-notification');
  const notifText = document.getElementById('notif-body-text');

  if (!phone || !notif || !notifText) return;

  // Make the smartphone shake & glow to simulate real notification alert
  phone.classList.add('glowing');
  setTimeout(() => phone.classList.remove('glowing'), 1500);

  // Set notification text
  notifText.innerHTML = `🚨 <strong>Threat:</strong> ${esc(pkgName.split('.').pop())}<br>Risk score: <span style="color:#ff3b30;font-weight:700">${score}/100</span>`;
  
  // Slide down notification
  notif.style.display = 'block';

  // Play a beautiful synthetic audio chime if browser context is unblocked
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    
    // Quick dual-tone chime
    osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    osc.start();
    
    osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.15); // A5
    setTimeout(() => {
      osc.stop();
      audioCtx.close();
    }, 350);
  } catch (_) {}
}

function resetVirtualPhone() {
  const notif = document.getElementById('phone-notification');
  const body = document.getElementById('phone-screen-body');
  if (notif) notif.style.display = 'none';

  if (body) {
    body.innerHTML = `
      <div class="phone-lockscreen" id="phone-lockscreen-view">
        <div class="lockscreen-clock" id="lockscreen-clock-text">22:42</div>
        <div class="lockscreen-date" id="lockscreen-date-text">Thursday, May 28</div>
        <div class="lockscreen-hint">🔒 CSO Mobilestation</div>
      </div>
    `;
    updateVirtualPhoneClock();
  }
}

function openVirtualWhatsApp() {
  const notif = document.getElementById('phone-notification');
  const body = document.getElementById('phone-screen-body');
  if (notif) notif.style.display = 'none';

  if (!body) return;

  // Render a high-fidelity WhatsApp screen
  body.innerHTML = `
    <div class="phone-chat-screen">
      <div class="phone-chat-header">
        <span style="font-size:0.7rem">🟢</span>
        <div>
          <div style="font-size:0.55rem;color:#fff">GAGMA Threat Bot</div>
          <div style="font-size:0.4rem;color:rgba(255,255,255,0.4);font-weight:400">online</div>
        </div>
      </div>
      <div class="phone-chat-messages" id="phone-chat-logs">
        <div class="phone-bubble incoming">
          🚨 <strong>CRITICAL INCIDENT ALERT</strong><br><br>
          Malware detected on host node.<br>
          ■ <strong>APK:</strong> ${esc(activeAlertPkg)}<br>
          ■ <strong>Risk:</strong> ${activeAlertScore}/100<br><br>
          Seeding system firewalls.
        </div>
        <div class="phone-bubble incoming" id="phone-threat-recomm">
          Recommended countermeasure: <strong>QUARANTINE_DEVICE</strong>. Tap below to dispatch.
        </div>
      </div>
      <div style="padding:4px;border-top:1px solid rgba(255,255,255,0.05);display:flex;justify-content:center" id="phone-chat-input-area">
        <button id="btn-phone-quarantine" style="background:#ff3b30;color:#fff;border:none;border-radius:4px;padding:3px 8px;font-size:0.45rem;font-weight:700;cursor:pointer;width:95%">
          Lock & Quarantine Device
        </button>
      </div>
    </div>
  `;

  // Attach button triggers inside phone
  const qBtn = document.getElementById('btn-phone-quarantine');
  if (qBtn) {
    qBtn.addEventListener('click', () => {
      const logs = document.getElementById('phone-chat-logs');
      const inputArea = document.getElementById('phone-chat-input-area');
      if (logs) {
        // User response bubble
        const userBubble = document.createElement('div');
        userBubble.className = 'phone-bubble outgoing';
        userBubble.textContent = 'Command Authorized: Dispatching Lock';
        logs.appendChild(userBubble);
        logs.scrollTop = logs.scrollHeight;

        // Bot response bubble
        setTimeout(() => {
          const replyBubble = document.createElement('div');
          replyBubble.className = 'phone-bubble incoming';
          replyBubble.innerHTML = '🛡️ <strong>MDM Payload Dispatched:</strong> quarantine completed. Device lock active.';
          logs.appendChild(replyBubble);
          logs.scrollTop = logs.scrollHeight;
        }, 800);
      }
      if (inputArea) {
        inputArea.innerHTML = '<span style="font-size:0.4rem;color:#00ff66;font-family:var(--mono)">Incident Resolved (MDM Active)</span>';
      }
    });
  }
}
