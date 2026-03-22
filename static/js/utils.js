/**
 * DNS Panel shared utilities.
 *
 * Provides:
 *  - Toast notifications (showToast)
 *  - Safe clipboard copy (copyToClipboard)
 *  - Accessible modal helpers (openModal / closeModal)
 *  - Visibility-aware polling (createPoller)
 */

/* ── Toast Notifications ── */

const _toastContainer = (() => {
  let el = document.getElementById('_toastContainer');
  if (!el) {
    el = document.createElement('div');
    el.id = '_toastContainer';
    el.className = 'fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none';
    el.setAttribute('aria-live', 'polite');
    document.body.appendChild(el);
  }
  return el;
})();

/**
 * Show a brief toast notification.
 * @param {'success'|'error'|'info'|'warning'} type
 * @param {string} message
 * @param {number} [duration=3000]
 */
function showToast(type, message, duration = 3000) {
  const palette = {
    success: 'bg-emerald-600 text-white',
    error: 'bg-red-600 text-white',
    warning: 'bg-amber-500 text-white',
    info: 'bg-blue-600 text-white',
  };
  const toast = document.createElement('div');
  toast.className = `pointer-events-auto rounded-xl px-4 py-2.5 text-sm shadow-lg transition-all duration-300 ${palette[type] || palette.info}`;
  toast.setAttribute('role', 'alert');
  toast.textContent = message;
  _toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-x-4');
    setTimeout(() => toast.remove(), 320);
  }, duration);
}

/* ── Clipboard ── */

/**
 * Copy text to clipboard with visual feedback on a button.
 * @param {string} text
 * @param {HTMLElement} [btn] - optional button to show "已复制" feedback
 */
async function copyToClipboard(text, btn) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '已复制 ✓';
      btn.classList.add('bg-emerald-600', 'text-white');
      setTimeout(() => {
        btn.textContent = orig;
        btn.classList.remove('bg-emerald-600', 'text-white');
      }, 1500);
    }
  } catch {
    showToast('error', '复制失败，请手动选择文本复制');
  }
}

/* ── Modal Helpers (Accessible) ── */

let _previouslyFocused = null;

/**
 * Open a modal dialog accessibly.
 * @param {HTMLElement} modalEl
 */
function openModal(modalEl) {
  if (!modalEl) return;
  _previouslyFocused = document.activeElement;
  modalEl.setAttribute('role', 'dialog');
  modalEl.setAttribute('aria-modal', 'true');
  modalEl.classList.remove('hidden');
  modalEl.classList.add('flex');

  const focusable = modalEl.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (focusable) focusable.focus();
}

/**
 * Close a modal dialog accessibly.
 * @param {HTMLElement} modalEl
 */
function closeModal(modalEl) {
  if (!modalEl) return;
  modalEl.classList.add('hidden');
  modalEl.classList.remove('flex');
  if (_previouslyFocused && typeof _previouslyFocused.focus === 'function') {
    _previouslyFocused.focus();
  }
}

/**
 * Setup standard modal behaviour: close on backdrop click and Escape key.
 * @param {HTMLElement} modalEl
 * @param {HTMLElement|null} [cancelBtn]
 */
function setupModal(modalEl, cancelBtn) {
  if (!modalEl) return;
  modalEl.addEventListener('click', (e) => {
    if (e.target === modalEl) closeModal(modalEl);
  });
  if (cancelBtn) {
    cancelBtn.addEventListener('click', () => closeModal(modalEl));
  }
  modalEl.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal(modalEl);

    // Trap focus within modal
    if (e.key === 'Tab') {
      const focusable = modalEl.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });
}

/* ── Visibility-Aware Polling ── */

/**
 * Create a polling loop that pauses when the page is hidden.
 * @param {Function} fn - async function to call each interval
 * @param {number} intervalMs - polling interval in milliseconds
 * @returns {{ start(): void, stop(): void }} controller
 */
function createPoller(fn, intervalMs) {
  let timer = null;
  let running = false;

  function tick() {
    if (!running) return;
    Promise.resolve(fn()).catch(() => {}).finally(() => {
      if (running) timer = setTimeout(tick, intervalMs);
    });
  }

  function start() {
    if (running) return;
    running = true;
    tick();
  }

  function stop() {
    running = false;
    if (timer) { clearTimeout(timer); timer = null; }
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stop();
    } else {
      start();
    }
  });

  return { start, stop };
}
