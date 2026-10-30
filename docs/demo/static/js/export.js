// static/js/export.js -- export page (plain script, no imports)
(() => {
    const select = document.getElementById('alertSelect');
    const button = document.getElementById('exportPcapBtn');
    const msg = document.getElementById('exportMsg');
    if (!select || !button) return;
    const token = localStorage.getItem('ids_token') || '';
    const say = (text, bad) => { msg.textContent = text; msg.className = bad ? 'msg-err' : 'msg-ok'; };

    fetch('/alerts/history?limit=100').then(r => r.json()).then(rows => {
        if (!Array.isArray(rows)) return;
        for (const a of rows) {
            const label = `${new Date(a.timestamp).toLocaleString()}  ${a.outcome}  ${a.src_ip} -> ${a.dst_ip}`;
            select.add(new Option(label, a.id));          // Option text is never parsed as HTML
        }
    }).catch(() => say('Could not load alerts.', true));

    button.addEventListener('click', async () => {
        if (!select.value) return say('Select an alert first.', true);
        say('Preparing capture... (live alerts record the next few seconds of traffic)');
        button.disabled = true;
        try {
            const r = await fetch('/export/alert_pcap?id=' + encodeURIComponent(select.value),
                                  { headers: token ? { 'X-IDS-Token': token } : {} });
            if (!r.ok) {
                const err = await r.json().catch(() => ({}));
                return say(err.error || `Export failed (${r.status})`, true);
            }
            const url = URL.createObjectURL(await r.blob());
            const a = Object.assign(document.createElement('a'), { href: url, download: `alert-${select.value}.pcap` });
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(url);
            say(r.headers.get('X-Export-Mode') === 'replay-filter'
                ? 'Done: packets filtered from the replayed capture.'
                : 'Done: recorded the next packets between these hosts.');
        } catch (e) { say('Export failed.', true); }
        finally { button.disabled = false; }
    });
})();
