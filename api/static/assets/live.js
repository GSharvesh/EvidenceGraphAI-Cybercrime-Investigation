/**
 * EvidenceGraphAI — SSE Live-Update Client Module
 *
 * Manages EventSource connections to /sse/ledger, /sse/graph, and
 * /sse/status with exponential backoff reconnection and connection
 * state reporting.
 *
 * @module live
 */

import { updateNavLive } from '/static/assets/nav.js';

/** @type {Map<string, {source: EventSource, backoff: number}>} */
const _streams = new Map();

const BACKOFF_INITIAL = 1000;
const BACKOFF_MAX = 30000;
const BACKOFF_FACTOR = 2;

/**
 * Internal: creates a managed EventSource with exponential backoff.
 * @param {string} key - Stream identifier
 * @param {string} url - SSE endpoint URL
 * @param {Object<string, function>} listeners - Event name to handler map
 * @param {function} [onError] - Error callback
 * @returns {EventSource}
 */
function _createStream(key, url, listeners, onError) {
  // Close existing stream if present
  if (_streams.has(key)) {
    _streams.get(key).source.close();
  }

  let backoff = BACKOFF_INITIAL;
  let reconnectTimer = null;

  function connect() {
    const source = new EventSource(url);

    source.onopen = () => {
      backoff = BACKOFF_INITIAL; // Reset backoff on successful connection
      updateNavLive('live');
    };

    // Register typed event listeners
    for (const [eventName, handler] of Object.entries(listeners)) {
      source.addEventListener(eventName, (evt) => {
        try {
          const data = JSON.parse(evt.data);
          handler(data);
        } catch (err) {
          console.warn(`[live] Failed to parse ${eventName}:`, err);
        }
      });
    }

    source.onerror = (evt) => {
      console.warn(`[live] SSE ${key} error`, evt);
      updateNavLive('reconnecting');
      if (onError) onError(evt);

      // EventSource auto-reconnects, but if connection is CLOSED we do manual backoff
      if (source.readyState === EventSource.CLOSED) {
        _streams.delete(key);
        reconnectTimer = setTimeout(() => {
          backoff = Math.min(backoff * BACKOFF_FACTOR, BACKOFF_MAX);
          connect();
        }, backoff);
      }
    };

    _streams.set(key, { source, backoff, reconnectTimer });
    return source;
  }

  return connect();
}

/**
 * Connects to /sse/ledger and invokes callback for each ledger_entry event.
 * @param {function(Object): void} onEntry
 * @param {function(Event): void} [onError]
 * @returns {EventSource}
 */
export function connectLedgerStream(onEntry, onError) {
  return _createStream('ledger', '/sse/ledger', {
    ledger_entry: onEntry,
  }, onError);
}

/**
 * Connects to /sse/graph and invokes callbacks for graph mutation events.
 * @param {Object} handlers
 * @param {function(Object): void} [handlers.onNodeCreated]
 * @param {function(Object): void} [handlers.onEdgeCreated]
 * @param {function(Object): void} [handlers.onNodeUpdated]
 * @param {function(Event): void} [handlers.onError]
 * @returns {EventSource}
 */
export function connectGraphStream(handlers = {}) {
  const listeners = {};
  if (handlers.onNodeCreated) listeners.node_created = handlers.onNodeCreated;
  if (handlers.onEdgeCreated) listeners.edge_created = handlers.onEdgeCreated;
  if (handlers.onNodeUpdated) listeners.node_updated = handlers.onNodeUpdated;
  return _createStream('graph', '/sse/graph', listeners, handlers.onError);
}

/**
 * Connects to /sse/status and invokes callback for each status event.
 * @param {function(Object): void} onStatus
 * @param {function(Event): void} [onError]
 * @returns {EventSource}
 */
export function connectStatusStream(onStatus, onError) {
  return _createStream('status', '/sse/status', {
    status: onStatus,
  }, onError);
}

/**
 * Disconnects a specific stream by key.
 * @param {string} key - 'ledger'|'graph'|'status'
 */
export function disconnectStream(key) {
  const entry = _streams.get(key);
  if (entry) {
    entry.source.close();
    if (entry.reconnectTimer) clearTimeout(entry.reconnectTimer);
    _streams.delete(key);
  }
  if (_streams.size === 0) {
    updateNavLive('disconnected');
  }
}

/**
 * Disconnects all active SSE streams.
 */
export function disconnectAll() {
  for (const key of [..._streams.keys()]) {
    disconnectStream(key);
  }
  updateNavLive('disconnected');
}

/**
 * Returns the current connection state.
 * @returns {'live'|'reconnecting'|'disconnected'}
 */
export function getConnectionState() {
  if (_streams.size === 0) return 'disconnected';
  for (const { source } of _streams.values()) {
    if (source.readyState === EventSource.CONNECTING) return 'reconnecting';
  }
  return 'live';
}
