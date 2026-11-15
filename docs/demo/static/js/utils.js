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
    // Only needed when the server runs with IDS_API_TOKEN.
    token() { return localStorage.getItem('ids_token') || ''; },
    headers() { const t = this.token(); return t ? { 'X-IDS-Token': t } : {}; },
    withToken(url) {
        const t = this.token();
        return t ? `${url}${url.includes('?') ? '&' : '?'}token=${encodeURIComponent(t)}` : url;
    },
};
