// static/js/settings.js -- settings page (plain script, no imports)
(() => {
    const form = document.getElementById('settingsForm');
    if (!form) return;
    const msg = document.getElementById('settingsMsg');
    const token = localStorage.getItem('ids_token') || '';

    fetch('/api/interfaces').then(r => r.json()).then(d => {
        const list = document.getElementById('ifaceList');
        for (const name of (d.capture_interfaces && d.capture_interfaces.length ? d.capture_interfaces : d.interfaces) || [])
            list.appendChild(new Option(name, name));
    }).catch(() => {});

    form.addEventListener('submit', async e => {
        e.preventDefault();
        const body = {};
        new FormData(form).forEach((v, k) => { body[k] = v; });
        try {
            const r = await fetch('/settings/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...(token ? { 'X-IDS-Token': token } : {}) },
                body: JSON.stringify(body),
            });
            const data = await r.json().catch(() => ({}));
            if (r.ok) {
                msg.textContent = data.restart_required
                    ? 'Saved. Stop and start the IDS for the interface/filter change to apply.' : 'Saved.';
                msg.className = 'msg-ok';
            } else {
                msg.textContent = (data.errors || [data.error || `Error ${r.status}`]).join(' | ');
                msg.className = 'msg-err';
            }
        } catch (err) { msg.textContent = 'Could not reach the server.'; msg.className = 'msg-err'; }
    });
})();
