// Static-demo shim. Replaces Socket.IO and the server API with a recorded run
// (docs/demo/events.json), so the real dashboard JS runs on GitHub Pages with no server.
(() => {
    'use strict';
    const realFetch = window.fetch.bind(window);
    const ss = window.sessionStorage;
    const K = { start: 'demo_start', frozen: 'demo_frozen', acks: 'demo_acks' };
    const handlers = {}, latest = {};
    let events = [], timers = [], endT = 0;
    const acks = JSON.parse(ss.getItem(K.acks) || '{}');

    const fire = (name, data) => { if (handlers[name]) handlers[name](data); };
    const deliver = ev => {
        let data = ev.data;
        if (ev.name === 'alert_update')            // overlay acknowledgements made in this demo
            data = { alerts: data.alerts.map(a => (latest[a.id] = { ...a, ...(acks[a.id] || {}) })) };
        fire(ev.name, data);
    };
    const elapsed = () => ss.getItem(K.frozen) !== null ? +ss.getItem(K.frozen) : Date.now() - +ss.getItem(K.start);

    function play() {                                // also catches up after navigating to another page
        const now = elapsed();
        events.filter(e => e.t <= now).forEach(deliver);
        if (ss.getItem(K.frozen) !== null) return fire('status_update', { status: 'IDS Stopped', color: 'info', running: false });
        events.filter(e => e.t > now).forEach(e => timers.push(setTimeout(() => deliver(e), e.t - now)));
    }

    const socket = {
        on(name, fn) { handlers[name] = fn; },
        emit(name, data) {
            data = data || {};
            if (name === 'start_ids') {               // restart the recording
                ss.setItem(K.start, Date.now()); ss.removeItem(K.frozen); ss.removeItem(K.acks); location.reload();
            } else if (name === 'stop_ids') {
                const t = Math.min(elapsed(), endT);
                timers.forEach(clearTimeout); timers = [];
                ss.setItem(K.frozen, t);
                fire('status_update', { status: 'IDS Stopped', color: 'info', running: false });
            } else if ((name === 'ack_alert' || name === 'investigate_alert') && latest[data.id]) {
                const prev = acks[data.id] || {};
                acks[data.id] = { ...prev, acknowledged: true, acknowledged_timestamp: new Date().toISOString() };
                if (name === 'investigate_alert') Object.assign(acks[data.id], {
                    investigated: true,
                    investigator_notes: [...(prev.investigator_notes || []), { note: data.note || 'Investigated',
                        timestamp: new Date().toISOString(), false_positive: !!data.false_positive, investigator: data.investigator || null }],
                });
                ss.setItem(K.acks, JSON.stringify(acks));
                deliver({ name: 'alert_update', data: { alerts: [latest[data.id]] } });
            }
        },
    };

    window.io = () => {
        setTimeout(() => {
            fire('connect');
            realFetch('events.json').then(r => r.json()).then(list => {
                events = list; endT = list.length ? list[list.length - 1].t : 0;
                if (ss.getItem(K.start) === null) ss.setItem(K.start, Date.now());
                play();
            });
        }, 0);
        return socket;
    };

    const json = (body, ok = true, status = 200) => ({ ok, status, headers: { get: () => null },
        json: async () => body, blob: async () => new Blob([]) });
    window.fetch = async (url, opts) => {
        const u = String(url);
        if (u.startsWith('/api/pcaps')) return json({ pcaps: [{ name: 'demo_mixed.pcap', size: 0 }] });
        if (u.startsWith('/api/interfaces')) return json({ interfaces: ['eth0'], capture_interfaces: ['eth0'], current: 'eth0' });
        if (u.startsWith('/alerts/history')) return json(Object.values(latest));
        if (u.startsWith('/settings/update')) return json({ errors: ['Demo mode: settings are not saved.'] }, false, 400);
        if (u.startsWith('/export/')) return json({ error: 'Not available in the static demo' }, false, 404);
        return realFetch(url, opts);
    };

    document.addEventListener('click', e => {        // downloads need a running sensor
        const a = e.target.closest && e.target.closest('a[href^="/export/"]');
        if (a) { e.preventDefault(); alert('Downloads are not available in the static demo (they need a running sensor).'); }
    }, true);

    const banner = () => {
        const b = document.createElement('div');
        b.setAttribute('style', 'position:sticky;top:0;z-index:1000;background:#1e3a8a;color:#fff;padding:8px 12px;text-align:center;font:14px sans-serif');
        b.innerHTML = 'Demo mode: a recorded replay of <code>demo_mixed.pcap</code>, no server running. Click <b>Start IDS</b> to replay it. ' +
            '<a style="color:#bfdbfe" href="https://github.com/KarimSec811/ids-dashboard">Source on GitHub</a>';
        document.body.insertAdjacentElement('afterbegin', b);
    };
    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', banner) : banner();
})();
