/**
 * EvidenceGraphAI — System Status Widget Module
 *
 * Connects to the /sse/status stream and updates both the nav-bar
 * status dot and an optional on-page status panel showing per-service
 * health (Neo4j, Postgres, MinIO, Redis, Ledger).
 *
 * Usage:
 *   import { initStatusWidget } from '/static/assets/status.js';
 *   initStatusWidget();  // connects SSE and updates nav + optional panel
 *
 * @module status
 */

import { connectStatusStream } from '/static/assets/live.js';
import { updateNavStatus } from '/static/assets/nav.js';

const STATUS_PANEL_CSS = `
  #ega-status-panel {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 6px 14px;
    background: rgba(13, 18, 32, 0.85);
    border: 1px solid #232f48;
    border-radius: 8px;
    font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
    font-size: 11px;
    color: #94a3b8;
    flex-wrap: wrap;
  }
  .ega-svc {
    display: flex;
    align-items: center;
    gap: 5px;
  }
  .ega-svc-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: #64748b;
    transition: background 0.3s, box-shadow 0.3s;
  }
  .ega-svc-dot.up {
    background: #10b981;
    box-shadow: 0 0 6px #10b981;
  }
  .ega-svc-dot.down {
    background: #ef4444;
    box-shadow: 0 0 6px #ef4444;
  }
`;

/** @type {Object|null} Latest status snapshot */
let _lastStatus = null;

/**
 * Evaluates aggregate system health.
 * @param {Object} s - StatusEvent payload
 * @returns {'ok'|'degraded'|'down'}
 */
function evaluateHealth(s) {
  const services = [s.neo4j, s.postgres, s.minio, s.redis];
  const upCount = services.filter(Boolean).length;
  if (upCount === 4) return 'ok';
  if (upCount >= 2) return 'degraded';
  return 'down';
}

/**
 * Returns a human label for health state.
 * @param {'ok'|'degraded'|'down'} health
 * @param {Object} s
 * @returns {string}
 */
function healthLabel(health, s) {
  if (health === 'ok') return `All Services OK · ${s.ledger_entries} Blocks`;
  if (health === 'degraded') return 'Degraded';
  return 'Services Down';
}

/**
 * Creates or returns an on-page status panel element.
 * Caller decides where to insert it.
 * @returns {HTMLElement}
 */
export function createStatusPanel() {
  const existing = document.getElementById('ega-status-panel');
  if (existing) return existing;

  // Inject CSS
  const style = document.createElement('style');
  style.textContent = STATUS_PANEL_CSS;
  document.head.appendChild(style);

  const panel = document.createElement('div');
  panel.id = 'ega-status-panel';
  panel.innerHTML = `
    <div class="ega-svc"><span class="ega-svc-dot" id="svc-neo4j"></span> Neo4j</div>
    <div class="ega-svc"><span class="ega-svc-dot" id="svc-postgres"></span> Postgres</div>
    <div class="ega-svc"><span class="ega-svc-dot" id="svc-minio"></span> MinIO</div>
    <div class="ega-svc"><span class="ega-svc-dot" id="svc-redis"></span> Redis</div>
    <div class="ega-svc"><span class="ega-svc-dot" id="svc-ledger"></span> Ledger <span id="svc-ledger-count"></span></div>
  `;
  return panel;
}

/**
 * Updates the on-page status panel with latest data.
 * @param {Object} s
 */
function updatePanel(s) {
  const setDot = (id, ok) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'ega-svc-dot ' + (ok ? 'up' : 'down');
  };
  setDot('svc-neo4j', s.neo4j);
  setDot('svc-postgres', s.postgres);
  setDot('svc-minio', s.minio);
  setDot('svc-redis', s.redis);
  setDot('svc-ledger', s.ledger_intact);

  const countEl = document.getElementById('svc-ledger-count');
  if (countEl) countEl.textContent = `(${s.ledger_entries})`;
}

/**
 * Initializes the status widget: connects SSE, updates nav dot + panel.
 * @param {HTMLElement} [panelContainer] - If provided, the status panel is appended here
 */
export function initStatusWidget(panelContainer) {
  if (panelContainer) {
    const panel = createStatusPanel();
    panelContainer.appendChild(panel);
  }

  connectStatusStream(
    (status) => {
      _lastStatus = status;
      const health = evaluateHealth(status);
      updateNavStatus(health, healthLabel(health, status));
      updatePanel(status);
    },
    () => {
      updateNavStatus('down', 'SSE Disconnected');
    }
  );
}

/**
 * Returns the latest status snapshot, if available.
 * @returns {Object|null}
 */
export function getLastStatus() {
  return _lastStatus;
}
