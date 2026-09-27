/**
 * EvidenceGraphAI — Micro-Animations Module
 *
 * Provides subtle CSS-based animations injected at runtime.
 * All animations respect prefers-reduced-motion.
 *
 * @module animations
 */

import { prefersReducedMotion } from '/static/assets/utils.js';

const ANIM_CSS = `
  @keyframes ega-fade-in {
    from { opacity: 0; }
    to   { opacity: 1; }
  }
  @keyframes ega-slide-in-up {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes ega-pulse-once {
    0%   { transform: scale(1); }
    50%  { transform: scale(1.08); }
    100% { transform: scale(1); }
  }
  @keyframes ega-glow-border {
    0%   { box-shadow: 0 0 0 rgba(0, 229, 255, 0); }
    50%  { box-shadow: 0 0 12px rgba(0, 229, 255, 0.35); }
    100% { box-shadow: 0 0 0 rgba(0, 229, 255, 0); }
  }
  @keyframes ega-flash-bg {
    0%   { background-color: rgba(0, 229, 255, 0.15); }
    100% { background-color: transparent; }
  }
  .ega-anim-fade-in {
    animation: ega-fade-in 0.35s ease-out forwards;
  }
  .ega-anim-slide-in-up {
    animation: ega-slide-in-up 0.4s ease-out forwards;
    opacity: 0;
  }
  .ega-anim-pulse-once {
    animation: ega-pulse-once 0.5s ease-in-out;
  }
  .ega-anim-glow {
    animation: ega-glow-border 1s ease-in-out;
  }
  .ega-anim-flash-bg {
    animation: ega-flash-bg 1.2s ease-out forwards;
  }

  @media (prefers-reduced-motion: reduce) {
    .ega-anim-fade-in,
    .ega-anim-slide-in-up,
    .ega-anim-pulse-once,
    .ega-anim-glow,
    .ega-anim-flash-bg {
      animation: none !important;
      opacity: 1 !important;
      transform: none !important;
    }
  }
`;

let _injected = false;

function ensureCSS() {
  if (_injected) return;
  const style = document.createElement('style');
  style.textContent = ANIM_CSS;
  document.head.appendChild(style);
  _injected = true;
}

/**
 * Plays a fade-in animation on an element.
 * @param {HTMLElement} el
 * @param {number} [delayMs=0]
 */
export function fadeIn(el, delayMs = 0) {
  ensureCSS();
  if (prefersReducedMotion()) { el.style.opacity = '1'; return; }
  el.style.opacity = '0';
  setTimeout(() => {
    el.classList.add('ega-anim-fade-in');
    el.addEventListener('animationend', () => {
      el.classList.remove('ega-anim-fade-in');
      el.style.opacity = '1';
    }, { once: true });
  }, delayMs);
}

/**
 * Plays a slide-in-up animation on an element.
 * @param {HTMLElement} el
 * @param {number} [delayMs=0]
 */
export function slideInUp(el, delayMs = 0) {
  ensureCSS();
  if (prefersReducedMotion()) { el.style.opacity = '1'; return; }
  el.style.opacity = '0';
  el.style.animationDelay = `${delayMs}ms`;
  el.classList.add('ega-anim-slide-in-up');
  el.addEventListener('animationend', () => {
    el.classList.remove('ega-anim-slide-in-up');
    el.style.opacity = '1';
    el.style.animationDelay = '';
  }, { once: true });
}

/**
 * Plays a single pulse (scale bounce) animation.
 * @param {HTMLElement} el
 */
export function pulseOnce(el) {
  ensureCSS();
  if (prefersReducedMotion()) return;
  el.classList.remove('ega-anim-pulse-once');
  void el.offsetWidth;
  el.classList.add('ega-anim-pulse-once');
  el.addEventListener('animationend', () => {
    el.classList.remove('ega-anim-pulse-once');
  }, { once: true });
}

/**
 * Plays a cyan glow border animation.
 * @param {HTMLElement} el
 */
export function glowBorder(el) {
  ensureCSS();
  if (prefersReducedMotion()) return;
  el.classList.remove('ega-anim-glow');
  void el.offsetWidth;
  el.classList.add('ega-anim-glow');
  el.addEventListener('animationend', () => {
    el.classList.remove('ega-anim-glow');
  }, { once: true });
}

/**
 * Plays a brief cyan background flash animation (for new list items).
 * @param {HTMLElement} el
 */
export function flashBackground(el) {
  ensureCSS();
  if (prefersReducedMotion()) return;
  el.classList.add('ega-anim-flash-bg');
  el.addEventListener('animationend', () => {
    el.classList.remove('ega-anim-flash-bg');
  }, { once: true });
}

/**
 * Animates a numeric count from one value to another with ease-out.
 * @param {HTMLElement} el - Element to update
 * @param {number} from - Starting value
 * @param {number} to - Target value
 * @param {number} [duration=400] - Duration in ms
 */
export function animateCountUp(el, from, to, duration = 400) {
  if (prefersReducedMotion() || from === to) {
    el.textContent = String(to);
    return;
  }
  const startTime = performance.now();
  const diff = to - from;

  function step(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // ease-out: 1 - (1 - t)^3
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(from + diff * eased);
    el.textContent = String(current);
    if (progress < 1) {
      requestAnimationFrame(step);
    }
  }

  requestAnimationFrame(step);
}
