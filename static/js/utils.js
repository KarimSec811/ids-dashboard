// static/js/utils.js -- small shared helpers
export const Utils = {
    // Escape anything that came from the network before putting it in innerHTML.
    // Reverse-DNS names, DNS query names and SNI are attacker-controlled.
    esc(value) {
        return String(value ?? '').replace(/[&<>"']/g, c =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    },
    formatTime(ts) {
        if (!ts) return '-';
        const d = new Date(ts);
        return isNaN(d) ? '-' : d.toLocaleString();
    },
    clock(ts) {
        const d = new Date(ts);
        return isNaN(d) ? '-' : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    },
    bytes(n) {
        n = +n || 0;
        return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
    },
    // Only needed when the server runs with IDS_API_TOKEN.
    token() { return localStorage.getItem('ids_token') || ''; },
    headers() { const t = this.token(); return t ? { 'X-IDS-Token': t } : {}; },
    withToken(url) {
        const t = this.token();
        return t ? `${url}${url.includes('?') ? '&' : '?'}token=${encodeURIComponent(t)}` : url;
    },
};
