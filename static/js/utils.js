// Shared utilities for DNS Panel (Go version)

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const colors = { success: 'bg-green-500', error: 'bg-red-500', info: 'bg-blue-500', warning: 'bg-yellow-500' };
    const el = document.createElement('div');
    el.className = `toast text-white text-sm px-4 py-2 rounded-lg shadow-lg ${colors[type] || colors.info}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 4000);
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('已复制到剪贴板', 'success');
    } catch {
        showToast('复制失败', 'error');
    }
}

function createPoller(fn, intervalMs) {
    let timer = null;
    function start() {
        stop();
        timer = setInterval(() => { if (!document.hidden) fn(); }, intervalMs);
    }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }
    document.addEventListener('visibilitychange', () => { document.hidden ? stop() : start(); });
    return { start, stop };
}
