/**
 * EvidenceGraphAI — Shared Navigation Bar Module
 *
 * Injects a unified top navigation bar into every developer page,
 * providing cross-page links, active-page highlighting, disabled
 * future placeholders, and a live SSE connection indicator.
 *
 * Usage: <script type="module" src="/static/assets/nav.js"></script>
 *
 * @module nav
 */

const NAV_PAGES = [
  { label: 'Forensic Ingest Console', href: '/dev/ingestion-portal', icon: '🔬' },
  { label: 'Graph Viewer', href: '/dev/viewer', icon: '🕸️' },
  { label: 'Swagger API', href: '/docs', icon: '📄', external: true },
];

const NAV_FUTURE = [
  { label: 'Similarity Explorer', icon: '🔍' },
  { label: 'Copilot', icon: '🤖' },
];

const NAV_CSS = `
  #ega-nav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(90deg, #0d1220 0%, #131a2e 100%);
    border-bottom: 1px solid #232f48;
    padding: 0 24px;
    height: 44px;
    font-family: 'Outfit', 'Segoe UI', system-ui, sans-serif;
    font-size: 13px;
    z-index: 9999;
    flex-shrink: 0;
    box-sizing: border-box;
  }
  #ega-nav * { box-sizing: border-box; }

  #ega-nav .ega-nav-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #e2e4f0;
    font-weight: 700;
    font-size: 14px;
    letter-spacing: -0.3px;
    text-decoration: none;
  }
  #ega-nav .ega-nav-brand-icon {
    width: 26px; height: 26px;
    background: linear-gradient(135deg, #00e5ff, #7c5cfc);
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 14px;
  }

  #ega-nav .ega-nav-links {
    display: flex;
    align-items: center;
    gap: 4px;
    list-style: none;
    margin: 0; padding: 0;
  }
  #ega-nav .ega-nav-links a,
  #ega-nav .ega-nav-links .ega-nav-disabled {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 14px;
    border-radius: 6px;
    color: #94a3b8;
    text-decoration: none;
    font-weight: 500;
    font-size: 12.5px;
    transition: background 0.15s, color 0.15s;
  }
  #ega-nav .ega-nav-links a:hover {
    background: rgba(255,255,255,0.06);
    color: #e2e4f0;
  }
  #ega-nav .ega-nav-links a.active {
    background: rgba(0, 229, 255, 0.1);
    color: #00e5ff;
    font-weight: 600;
  }
  #ega-nav .ega-nav-links .ega-nav-disabled {
    opacity: 0.35;
    cursor: not-allowed;
    pointer-events: none;
  }
  #ega-nav .ega-nav-links .nav-icon { font-size: 14px; }
  #ega-nav .ega-nav-future-tag {
    font-size: 9px;
    background: rgba(124, 92, 252, 0.2);
    color: #a78bfa;
    padding: 1px 5px;
    border-radius: 3px;
    margin-left: 2px;
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.5px;
  }
  #ega-nav .ega-nav-sep {
    width: 1px;
    height: 20px;
    background: #232f48;
    margin: 0 6px;
  }

  #ega-nav .ega-nav-right {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  #ega-nav-status {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
    color: #64748b;
    cursor: default;
  }
  #ega-nav-status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #64748b;
    transition: background 0.4s, box-shadow 0.4s;
  }
  #ega-nav-status-dot.ok {
    background: #10b981;
    box-shadow: 0 0 8px #10b981;
  }
  #ega-nav-status-dot.degraded {
    background: #f59e0b;
    box-shadow: 0 0 8px #f59e0b;
  }
  #ega-nav-status-dot.down {
    background: #ef4444;
    box-shadow: 0 0 8px #ef4444;
  }

  #ega-nav-live {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
  }
  #ega-nav-live-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: #64748b;
    transition: background 0.3s, box-shadow 0.3s;
  }
  #ega-nav-live-dot.live {
    background: #10b981;
    box-shadow: 0 0 6px #10b981;
  }
  #ega-nav-live-dot.reconnecting {
    background: #f59e0b;
    box-shadow: 0 0 6px #f59e0b;
  }
  #ega-nav-live-dot.disconnected {
    background: #ef4444;
    box-shadow: 0 0 6px #ef4444;
  }
  #ega-nav-live-label {
    color: #64748b;
  }
  #ega-nav-live-label.live { color: #10b981; }
  #ega-nav-live-label.reconnecting { color: #f59e0b; }
  #ega-nav-live-label.disconnected { color: #ef4444; }

  @media (prefers-reduced-motion: reduce) {
    #ega-nav * { transition: none !important; }
  }
`;

/**
 * Determines the current active page by matching pathname.
 * @returns {string} href of the active page
 */
function detectActivePage() {
  const path = window.location.pathname;
  for (const page of NAV_PAGES) {
    if (path === page.href || path.startsWith(page.href + '/')) {
      return page.href;
    }
  }
  return '';
}

/**
 * Renders the navigation bar and prepends it to <body>.
 */
export function injectNav() {
  if (document.getElementById('ega-nav')) return;

  // Inject CSS
  const style = document.createElement('style');
  style.textContent = NAV_CSS;
  document.head.appendChild(style);

  const activePath = detectActivePage();

  // Build active link items (all primary application links open in a new tab)
  const linksHtml = NAV_PAGES.map(page => {
    const cls = page.href === activePath ? 'active' : '';
    return `<a href="${page.href}" class="${cls}" target="_blank" rel="noopener noreferrer">
      <span class="nav-icon">${page.icon}</span>${page.label}
    </a>`;
  }).join('');

  // Build disabled future placeholders
  const futureHtml = NAV_FUTURE.map(page => {
    return `<span class="ega-nav-disabled" title="Coming in Phase 3">
      <span class="nav-icon">${page.icon}</span>${page.label}
      <span class="ega-nav-future-tag">Future</span>
    </span>`;
  }).join('');

  const nav = document.createElement('nav');
  nav.id = 'ega-nav';
  nav.innerHTML = `
    <a class="ega-nav-brand" href="/">
      <span class="ega-nav-brand-icon">EG</span>
      EvidenceGraphAI
    </a>
    <div class="ega-nav-links">
      ${linksHtml}
      <div class="ega-nav-sep"></div>
      ${futureHtml}
    </div>
    <div class="ega-nav-right">
      <div id="ega-nav-live">
        <span id="ega-nav-live-dot"></span>
        <span id="ega-nav-live-label">Connecting…</span>
      </div>
      <div id="ega-nav-status">
        <span id="ega-nav-status-dot"></span>
        <span id="ega-nav-status-label">—</span>
      </div>
    </div>
  `;
  document.body.prepend(nav);
}

/**
 * Updates the system status indicator dot in the nav bar.
 * @param {'ok'|'degraded'|'down'|'unknown'} state
 * @param {string} label
 */
export function updateNavStatus(state, label) {
  const dot = document.getElementById('ega-nav-status-dot');
  const lbl = document.getElementById('ega-nav-status-label');
  if (!dot || !lbl) return;

  dot.className = '';
  if (state === 'ok' || state === 'degraded' || state === 'down') {
    dot.classList.add(state);
  }
  lbl.textContent = label;
}

/**
 * Updates the live SSE connection indicator in the nav bar.
 * @param {'live'|'reconnecting'|'disconnected'} state
 */
export function updateNavLive(state) {
  const dot = document.getElementById('ega-nav-live-dot');
  const lbl = document.getElementById('ega-nav-live-label');
  if (!dot || !lbl) return;

  dot.className = '';
  lbl.className = '';
  dot.classList.add(state);
  lbl.classList.add(state);

  const labels = { live: 'Live', reconnecting: 'Reconnecting…', disconnected: 'Disconnected' };
  lbl.textContent = labels[state] || state;
}

// Auto-inject on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectNav);
} else {
  injectNav();
}
