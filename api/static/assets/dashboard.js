/**
 * dashboard.js — EvidenceGraphAI Phase 3 Vulnerability Intelligence Controller
 *
 * Implements:
 * - Hash SPA router (#/dashboard, #/analyze, #/blueprint, #/sandbox, #/mapper)
 * - Live SSE real-time stream listener (/sse/vulnerability and /sse/sandbox)
 * - Interactive CVE Explorer & Ingestion
 * - Comprehensive CVE Intelligence Viewer:
 *   • CVSS Metrics & Base Severity
 *   • CWE ID & Authoritative Name Resolution
 *   • Structured Affected Products & Vulnerable Version Ranges
 *   • Strict Remediation Semantics (Fixed Versions vs Commits vs Patch URLs vs Advisories)
 *   • Discovered PoC / Exploit Evidence
 *   • Evidence-based ATT&CK Technique Mappings
 *   • Fact-Level Source Provenance, Reliability & Retrieval Timestamps
 * - Threat Blueprint Cytoscape integration
 * - Isolated Sandbox Replay (dry-run & live container options)
 * - Rule-Based MITRE ATT&CK Text Mapper
 */

/* global BlueprintVisualizer */

const Dashboard = (() => {
  let blueprintViz = null;
  let activeBlueprint = null;
  let activeCVEAnalysis = null;
  let sseSource = null;

  // ── Router ────────────────────────────────────────────────────────
  function initRouter() {
    window.addEventListener('hashchange', handleRoute);
    handleRoute();
  }

  function handleRoute() {
    const hash = window.location.hash || '#/dashboard';
    const cleanHash = hash.split('?')[0];

    document.querySelectorAll('.page').forEach((el) => el.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach((el) => el.classList.remove('active'));

    const tabMap = {
      '#/dashboard': { page: 'page-dashboard', tab: 'tab-dashboard' },
      '#/analyze': { page: 'page-analyze', tab: 'tab-analyze' },
      '#/blueprint': { page: 'page-blueprint', tab: 'tab-blueprint' },
      '#/sandbox': { page: 'page-sandbox', tab: 'tab-sandbox' },
      '#/mapper': { page: 'page-mapper', tab: 'tab-mapper' }
    };

    const target = tabMap[cleanHash] || tabMap['#/dashboard'];
    const targetPage = document.getElementById(target.page);
    if (targetPage) targetPage.classList.add('active');

    const navLink = document.getElementById(target.tab);
    if (navLink) navLink.classList.add('active');

    if (cleanHash === '#/dashboard') {
      loadCVEList();
    }
  }

  // ── SSE Live Ticker ───────────────────────────────────────────────
  function initSSE() {
    if (!window.EventSource) return;
    try {
      sseSource = new EventSource('/sse/vulnerability');
      sseSource.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          appendTickerItem(data);
          incrementStat('stat-cves');
        } catch (e) {
          // heartbeat or non-json frame
        }
      };
      sseSource.onerror = () => {
        const dot = document.getElementById('sse-dot');
        if (dot) dot.style.background = '#FF2E2E';
      };
      sseSource.onopen = () => {
        const dot = document.getElementById('sse-dot');
        if (dot) dot.style.background = '#C6FF00';
      };
    } catch (e) {
      console.warn('SSE connection initialization skipped:', e);
    }
  }

  function appendTickerItem(data) {
    const list = document.getElementById('live-ticker-items');
    if (!list) return;
    const item = document.createElement('div');
    item.className = 'section';
    item.style.padding = '0.75rem 1rem';
    item.style.borderBottom = '2px solid #222';
    item.style.background = '#111';
    item.innerHTML = `
      <div class="flex justify-between align-center mono" style="font-size:0.65rem;">
        <span class="text-lime">[${new Date().toLocaleTimeString()}]</span>
        <span class="text-muted">${data.event_type || 'CVE_ANALYZED'}</span>
      </div>
      <div class="mono text-white" style="font-size:0.75rem;margin-top:0.25rem;">
        <strong>${data.cve_id || data.session_id || 'Update'}</strong>
        ${data.severity ? `<span class="badge badge--sm" style="margin-left:4px;">${data.severity}</span>` : ''}
      </div>
    `;
    list.prepend(item);
    if (list.children.length > 25) {
      list.removeChild(list.lastChild);
    }
  }

  function incrementStat(id) {
    const el = document.getElementById(id);
    if (el) {
      const val = parseInt(el.textContent, 10) || 0;
      el.textContent = val + 1;
    }
  }

  // ── CVE List Explorer ─────────────────────────────────────────────
  async function loadCVEList() {
    const container = document.getElementById('cve-list');
    if (!container) return;
    try {
      const resp = await fetch('/vulnerability/cves?limit=25');
      if (!resp.ok) throw new Error('Failed to load CVEs');
      const cves = await resp.json();
      const statEl = document.getElementById('stat-cves');
      if (statEl && cves.length) statEl.textContent = cves.length;

      if (!cves || cves.length === 0) {
        container.innerHTML = `<div class="section mono text-muted" style="font-size:0.75rem;padding:1rem;">No analyzed CVEs yet. Use ANALYZE CVE tab.</div>`;
        return;
      }

      container.innerHTML = cves.map(item => `
        <div class="section flex justify-between align-center" style="padding:0.75rem 1rem;border-bottom:1px solid #222;cursor:pointer;" onclick="Dashboard.selectCVE('${item.cve_id}')">
          <div>
            <strong class="mono text-lime" style="font-size:0.8rem;">${item.cve_id}</strong>
            <p class="mono text-muted" style="font-size:0.65rem;margin-top:2px;">${item.fetched_at ? item.fetched_at.slice(0, 19).replace('T', ' ') : ''}</p>
          </div>
          <button class="btn btn--sm" style="padding:2px 8px;font-size:0.65rem;">VIEW</button>
        </div>
      `).join('');
    } catch (err) {
      container.innerHTML = `<div class="section mono text-red" style="font-size:0.75rem;padding:1rem;">${err.message}</div>`;
    }
  }

  async function selectCVE(cveId) {
    const analyzeInput = document.getElementById('analyze-cve-input');
    if (analyzeInput) analyzeInput.value = cveId;
    window.location.hash = '#/analyze';
    await analyzeCVE(cveId);
  }

  // ── CVE Analysis ──────────────────────────────────────────────────
  async function analyzeCVE(cveId) {
    if (!cveId) {
      cveId = (document.getElementById('analyze-cve-input')?.value || '').trim();
    }
    if (!cveId) return;

    const btn = document.getElementById('analyze-btn');
    if (btn) btn.textContent = 'ANALYZING...';

    try {
      const resp = await fetch('/vulnerability/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_id: cveId })
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Analysis request failed');
      }
      const data = await resp.json();
      activeCVEAnalysis = data;
      renderAnalysisResult(data);
      incrementStat('stat-cves');
    } catch (err) {
      alert(`CVE Analysis Error: ${err.message}`);
    } finally {
      if (btn) btn.textContent = 'ANALYZE';
    }
  }

  function renderAnalysisResult(data) {
    const resultContainer = document.getElementById('analyze-result');
    if (!resultContainer) return;

    const cvss = data.cvss || {};
    const cvssScore = data.cvss_score !== null ? data.cvss_score.toFixed(1) : (cvss.base_score ? cvss.base_score.toFixed(1) : '--');
    const severity = data.severity || cvss.base_severity || 'UNKNOWN';

    // 1. Identity & CVSS Header
    document.getElementById('result-cve-id').textContent = data.cve_id;
    document.getElementById('cvss-score-val').textContent = cvssScore;
    const sevBadge = document.getElementById('severity-badge');
    sevBadge.textContent = severity;
    sevBadge.className = `badge badge--${severity.toLowerCase()}`;

    // Description
    document.getElementById('result-description').textContent = data.description || 'No description available in NVD record.';

    // Taxonomy & Surface
    const cweText = data.cwe_id ? (data.cwe_name ? `${data.cwe_id}: ${data.cwe_name}` : data.cwe_id) : 'None / Not Assigned';
    document.getElementById('result-cwe').textContent = cweText;
    document.getElementById('result-av').textContent = data.attack_vector || cvss.attack_vector || '--';
    document.getElementById('result-remote').textContent = data.remote_exploitable ? 'YES' : 'NO';
    document.getElementById('result-remote').className = `mono ${data.remote_exploitable ? 'text-red' : 'text-lime'}`;
    document.getElementById('result-auth').textContent = data.requires_auth ? 'REQUIRED' : 'NONE';

    // 2. Remediation Intelligence
    const rem = data.remediation || {};
    const patchInfo = data.patch_info || {};
    const remSourceBadge = document.getElementById('remediation-primary-source');
    const primarySource = rem.primary_source_type || patchInfo.source_type || 'unknown';
    remSourceBadge.textContent = `SOURCE: ${primarySource.toUpperCase()}`;
    remSourceBadge.className = rem.patch_available ? 'badge badge--lime' : (rem.fix_exists ? 'badge badge--hypo' : 'badge badge--danger');

    document.getElementById('remediation-summary').textContent = rem.summary || (patchInfo.fetch_error || 'Remediation status unavailable.');

    // Fixed Versions
    const fixedVerContainer = document.getElementById('result-fixed-versions');
    const fixedVers = rem.fixed_versions || patchInfo.fixed_versions || [];
    if (fixedVers.length > 0) {
      fixedVerContainer.innerHTML = fixedVers.map(v => `<span class="badge badge--lime">${v}</span>`).join(' ');
    } else {
      fixedVerContainer.innerHTML = `<span class="text-muted">None documented</span>`;
    }

    // Remediation Commits
    const commitsContainer = document.getElementById('result-commits');
    const commits = rem.remediation_commits || (patchInfo.commit_sha ? [patchInfo.commit_sha] : []);
    if (commits.length > 0) {
      commitsContainer.innerHTML = commits.map(c => `<code>${c.slice(0, 12)}</code>`).join(', ');
    } else {
      commitsContainer.innerHTML = `<span class="text-muted">None</span>`;
    }

    // Patch URLs
    const patchUrlsContainer = document.getElementById('result-patch-urls');
    const patchUrls = rem.patch_urls || data.patch_links || [];
    if (patchUrls.length > 0) {
      patchUrlsContainer.innerHTML = patchUrls.map(u => `<div><a href="${u}" target="_blank" rel="noopener noreferrer" class="text-lime" style="word-break:break-all;">${u}</a></div>`).join('');
    } else {
      patchUrlsContainer.innerHTML = `<span class="text-muted">No direct patch URLs</span>`;
    }

    // Advisory URLs
    const advisoryUrlsContainer = document.getElementById('result-advisory-urls');
    const advisoryUrls = rem.advisory_urls || data.advisory_links || [];
    if (advisoryUrls.length > 0) {
      advisoryUrlsContainer.innerHTML = advisoryUrls.map(u => `<div><a href="${u}" target="_blank" rel="noopener noreferrer" class="text-white" style="word-break:break-all;">${u}</a></div>`).join('');
    } else {
      advisoryUrlsContainer.innerHTML = `<span class="text-muted">No vendor advisory URLs</span>`;
    }

    // 3. Structured Affected Products Table
    const prodTbody = document.getElementById('products-tbody');
    const structuredProducts = data.structured_products || [];
    if (structuredProducts.length > 0) {
      prodTbody.innerHTML = structuredProducts.map(p => `
        <tr>
          <td class="mono font-bold text-white">${p.vendor}</td>
          <td class="mono text-lime">${p.product}</td>
          <td class="mono text-white">${p.version_range || 'all versions'}</td>
          <td class="mono text-muted" style="font-size:0.65rem;word-break:break-all;">${p.cpe23uri || '--'}</td>
        </tr>
      `).join('');
    } else if (data.cpe_matches && data.cpe_matches.length > 0) {
      prodTbody.innerHTML = data.cpe_matches.map(c => `
        <tr>
          <td class="mono text-muted" colspan="3">Legacy CPE Match</td>
          <td class="mono text-muted" style="font-size:0.65rem;word-break:break-all;">${c.cpe23uri}</td>
        </tr>
      `).join('');
    } else {
      prodTbody.innerHTML = `<tr><td colspan="4" class="mono text-muted">No affected product configurations cataloged</td></tr>`;
    }

    // 4. Exploit References
    const exploitSection = document.getElementById('exploit-section');
    const exploitList = document.getElementById('exploit-list');
    const exploits = data.exploit_references || [];
    if (exploits.length > 0) {
      exploitSection.style.display = 'block';
      exploitList.innerHTML = exploits.map(u => `<li><a href="${u}" target="_blank" rel="noopener noreferrer" style="color:#ff8888;word-break:break-all;">${u}</a></li>`).join('');
    } else {
      exploitSection.style.display = 'none';
    }

    // 5. ATT&CK Techniques Table
    const techTbody = document.getElementById('technique-tbody');
    const mappings = data.technique_mappings || [];
    if (mappings.length > 0) {
      techTbody.innerHTML = mappings.map(m => `
        <tr>
          <td class="mono font-bold text-lime">${m.technique_id}</td>
          <td class="font-bold text-white">${m.technique_name}</td>
          <td class="mono"><span class="badge badge--sm">${m.tactic}</span></td>
          <td class="mono text-lime">${(m.confidence * 100).toFixed(0)}%</td>
          <td class="text-muted" style="font-size:0.75rem;">${m.rationale}</td>
        </tr>
      `).join('');
      const statTech = document.getElementById('stat-techniques');
      if (statTech) statTech.textContent = mappings.length;
    } else {
      techTbody.innerHTML = `<tr><td colspan="5" class="mono text-muted">No ATT&amp;CK techniques identified for this profile</td></tr>`;
    }

    // 6. Fact Provenance Table
    const provTbody = document.getElementById('provenance-tbody');
    const provRecords = data.provenance_records || {};
    const provKeys = Object.keys(provRecords);
    if (provKeys.length > 0) {
      provTbody.innerHTML = provKeys.map(k => {
        const rec = provRecords[k];
        return `
          <tr>
            <td class="mono font-bold text-lime">${k.toUpperCase()}</td>
            <td class="mono text-white">${rec.source_name}</td>
            <td class="mono"><span class="badge badge--sm">${rec.source_type || 'unknown'}</span></td>
            <td class="mono text-lime">${(rec.confidence * 100).toFixed(0)}%</td>
            <td class="mono text-muted" style="font-size:0.65rem;">${rec.retrieved_at ? rec.retrieved_at.slice(0, 19).replace('T', ' ') : '--'}</td>
            <td class="text-muted" style="font-size:0.7rem;">${rec.notes || '--'}</td>
          </tr>
        `;
      }).join('');
    } else {
      provTbody.innerHTML = `<tr><td colspan="6" class="mono text-muted">No fact-level provenance recorded</td></tr>`;
    }

    // Show result container
    resultContainer.classList.add('visible');
  }

  // ── Threat Blueprint ──────────────────────────────────────────────
  async function generateBlueprint(cveId) {
    cveId = cveId || document.getElementById('bp-cve-input')?.value || activeCVEAnalysis?.cve_id;
    if (!cveId) return;

    window.location.hash = '#/blueprint';
    const bpInput = document.getElementById('bp-cve-input');
    if (bpInput) bpInput.value = cveId;

    const btn = document.getElementById('bp-btn');
    if (btn) btn.textContent = 'GENERATING...';

    try {
      const resp = await fetch('/vulnerability/blueprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_id: cveId })
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Blueprint generation failed');
      }
      activeBlueprint = await resp.json();
      renderBlueprint(activeBlueprint);
      incrementStat('stat-techniques');
    } catch (err) {
      alert(`Blueprint Error: ${err.message}`);
    } finally {
      if (btn) btn.textContent = 'GENERATE';
    }
  }

  function renderBlueprint(bp) {
    const resSec = document.getElementById('bp-result-section');
    if (resSec) resSec.style.display = 'block';

    document.getElementById('bp-id-label').textContent = `Blueprint ID: ${bp.blueprint_id} (${bp.cve_id})`;
    document.getElementById('bp-confidence-label').textContent = `Hypothesis Confidence: ${(bp.overall_confidence * 100).toFixed(0)}% | Techniques: ${bp.techniques.length} stages`;

    const edgesTbody = document.getElementById('edges-tbody');
    if (edgesTbody && bp.edges) {
      edgesTbody.innerHTML = bp.edges.map(e => `
        <tr>
          <td class="mono text-lime">${e.from_id}</td>
          <td class="mono text-lime">${e.to_id}</td>
          <td class="mono text-white">${(e.probability * 100).toFixed(0)}%</td>
          <td class="mono"><span class="badge badge--hypo">${e.status || 'hypothesized'}</span></td>
        </tr>
      `).join('');
    }
  }

  function goBlueprint() {
    if (activeCVEAnalysis) {
      generateBlueprint(activeCVEAnalysis.cve_id);
    } else {
      window.location.hash = '#/blueprint';
    }
  }

  // ── Sandbox Replay ────────────────────────────────────────────────
  async function startReplay() {
    const cveId = document.getElementById('sb-cve-id')?.value || activeCVEAnalysis?.cve_id;
    if (!cveId) return alert('Please provide a CVE ID');

    const bpId = document.getElementById('sb-blueprint-id')?.value || (activeBlueprint ? activeBlueprint.blueprint_id : `BP-${cveId}`);
    const logEl = document.getElementById('sb-log');
    if (logEl) logEl.textContent = `[ Executing sandbox replay for ${cveId}... ]\n`;

    try {
      const resp = await fetch('/sandbox/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_id: cveId, blueprint_id: bpId, dry_run: true })
      });
      if (!resp.ok) throw new Error('Sandbox replay failed');
      const session = await resp.json();
      renderSandboxResults(session);
      incrementStat('stat-sessions');
    } catch (err) {
      if (logEl) logEl.textContent += `\n[ERROR] ${err.message}`;
    }
  }

  function renderSandboxResults(session) {
    const logEl = document.getElementById('sb-log');
    if (logEl) {
      logEl.textContent = `SESSION: ${session.session_id}\nSTATUS: ${session.status.toUpperCase()}\n`;
      session.telemetry_artifacts.forEach(a => {
        logEl.textContent += `• [${a.artifact_type}] ${a.object_name} (${a.sha256.slice(0, 12)}...)\n`;
      });
      (session.technique_results || []).forEach(tr => {
        logEl.textContent += `• ${tr.technique_id} -> ${tr.status.toUpperCase()} (conf: ${tr.confidence})\n`;
      });
    }

    const resSec = document.getElementById('sb-results');
    if (resSec) resSec.style.display = 'block';

    const confirmed = (session.technique_results || []).filter(t => t.status === 'confirmed');
    const refuted = (session.technique_results || []).filter(t => t.status === 'refuted');

    document.getElementById('sb-confirmed').innerHTML = confirmed.map(t => `<div class="mono text-lime" style="margin-bottom:4px;">✔ ${t.technique_id} (conf: ${t.confidence})</div>`).join('') || '<div class="text-muted">None</div>';
    document.getElementById('sb-refuted').innerHTML = refuted.map(t => `<div class="mono text-red" style="margin-bottom:4px;">✖ ${t.technique_id}</div>`).join('') || '<div class="text-muted">None</div>';
    document.getElementById('sb-status').textContent = session.status.toUpperCase();
    document.getElementById('sb-session-id').textContent = session.session_id;

    if (confirmed.length) incrementStat('stat-confirmed');
  }

  function goSandboxFromBlueprint() {
    if (activeBlueprint) {
      window.location.hash = '#/sandbox';
      const cveInput = document.getElementById('sb-cve-id');
      const bpInput = document.getElementById('sb-blueprint-id');
      if (cveInput) cveInput.value = activeBlueprint.cve_id;
      if (bpInput) bpInput.value = activeBlueprint.blueprint_id;
    }
  }

  async function triggerReplay() {
    const cveInput = document.getElementById('sandbox-cve-input');
    const cveId = cveInput ? cveInput.value.trim() : '';
    if (!cveId) return alert('Enter CVE ID for replay');

    const logEl = document.getElementById('replay-log');
    if (logEl) logEl.textContent = `[ Triggering dry-run replay for ${cveId}... ]\n`;

    try {
      const resp = await fetch('/sandbox/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_id: cveId, blueprint_id: `BP-${cveId}`, dry_run: true })
      });
      if (!resp.ok) throw new Error('Replay trigger failed');
      const data = await resp.json();
      if (logEl) {
        logEl.textContent += `Session ${data.session_id} completed.\nStatus: ${data.status}\n`;
        (data.technique_results || []).forEach(tr => {
          logEl.textContent += `[${tr.status.toUpperCase()}] ${tr.technique_id} (conf: ${tr.confidence})\n`;
        });
      }
      incrementStat('stat-sessions');
    } catch (err) {
      if (logEl) logEl.textContent += `[ERROR] ${err.message}\n`;
    }
  }

  // ── ATT&CK Mapper ─────────────────────────────────────────────────
  async function mapEvidence() {
    const evId = document.getElementById('mapper-evidence-id')?.value || `EV-${Date.now()}`;
    const text = document.getElementById('mapper-text')?.value;
    if (!text) return alert('Please enter evidence text');

    try {
      const resp = await fetch('/attack/map', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence_id: evId, text: text })
      });
      if (!resp.ok) throw new Error('Mapping request failed');
      const matches = await resp.json();
      renderMapperResults(matches);
    } catch (err) {
      alert(`Mapper Error: ${err.message}`);
    }
  }

  function renderMapperResults(matches) {
    const resSec = document.getElementById('mapper-results');
    if (resSec) resSec.style.display = 'block';

    const tbody = document.getElementById('mapper-tbody');
    if (!matches || matches.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="mono text-muted">No ATT&amp;CK techniques matched in text</td></tr>`;
      return;
    }

    tbody.innerHTML = matches.map(m => `
      <tr>
        <td class="mono font-bold text-lime">${m.technique_id}</td>
        <td class="font-bold text-white">${m.technique_name}</td>
        <td class="mono"><span class="badge badge--sm">${m.tactic}</span></td>
        <td class="mono text-lime">${(m.confidence * 100).toFixed(0)}%</td>
        <td class="text-muted mono" style="font-size:0.75rem;">${m.rule_name || '--'}</td>
        <td class="mono text-blue" style="font-size:0.75rem;"><code>${m.matched_text || '--'}</code></td>
      </tr>
    `).join('');
  }

  // ── Public API ────────────────────────────────────────────────────
  return {
    init: () => {
      initRouter();
      initSSE();
    },
    analyzeCVE,
    selectCVE,
    loadCVEList,
    generateBlueprint,
    goBlueprint,
    startReplay,
    triggerReplay,
    goSandboxFromBlueprint,
    mapEvidence
  };
})();

// Global function bridges for HTML inline onclick handlers
function analyzeCV() { Dashboard.analyzeCVE(); }
function loadCVEList() { Dashboard.loadCVEList(); }
function goBlueprint() { Dashboard.goBlueprint(); }
function generateBlueprint() { Dashboard.generateBlueprint(); }
function startReplay() { Dashboard.startReplay(); }
function triggerReplay() { Dashboard.triggerReplay(); }
function goSandboxFromBlueprint() { Dashboard.goSandboxFromBlueprint(); }
function mapEvidence() { Dashboard.mapEvidence(); }

document.addEventListener('DOMContentLoaded', () => {
  Dashboard.init();
});

window.Dashboard = Dashboard;
