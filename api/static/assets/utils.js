/**
 * EvidenceGraphAI — Shared Utilities Module
 *
 * Provides reusable helpers for query parameter parsing,
 * safe HTML escaping, relative time formatting, and DOM utilities.
 *
 * @module utils
 */

/**
 * Returns a single query parameter value by name.
 * @param {string} name - Parameter name
 * @returns {string|null}
 */
export function getQueryParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

/**
 * Returns all query parameters as a plain object.
 * @returns {Object<string, string>}
 */
export function getQueryParams() {
  const params = new URLSearchParams(window.location.search);
  const result = {};
  for (const [key, value] of params.entries()) {
    result[key] = value;
  }
  return result;
}

/**
 * Escapes HTML special characters to prevent injection.
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(String(str)));
  return div.innerHTML;
}

/**
 * Formats a timestamp as relative time ("just now", "3 seconds ago", etc.).
 * @param {Date|number} timestamp
 * @returns {string}
 */
export function relativeTime(timestamp) {
  const now = Date.now();
  const ts = timestamp instanceof Date ? timestamp.getTime() : timestamp;
  const diffSec = Math.floor((now - ts) / 1000);

  if (diffSec < 3) return 'just now';
  if (diffSec < 60) return `${diffSec} seconds ago`;
  if (diffSec < 120) return '1 minute ago';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} minutes ago`;
  return `${Math.floor(diffSec / 3600)} hours ago`;
}

/**
 * Creates and starts a "last updated" ticker that updates an element's text.
 * @param {HTMLElement} el - Element to update
 * @param {string} [prefix='Updated'] - Prefix text
 * @returns {{ update: function(): void, stop: function(): void }}
 */
export function createLastUpdatedTicker(el, prefix = 'Updated') {
  let lastTs = Date.now();
  let intervalId = null;

  function render() {
    el.textContent = `${prefix} ${relativeTime(lastTs)}`;
  }

  function update() {
    lastTs = Date.now();
    render();
  }

  function stop() {
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
  }

  render();
  intervalId = setInterval(render, 1000);

  return { update, stop };
}

/**
 * Checks if prefers-reduced-motion is enabled.
 * @returns {boolean}
 */
export function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}
