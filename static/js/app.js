// static/js/app.js -- page controller: tables, filters, recent-alert feed, inspector, replay
import { Dashboard } from './dashboard.js';
import { SocketManager } from './socket.js';
import { Utils } from './utils.js';

const $ = id => document.getElementById(id);
const E = Utils.esc;
const sevOf = a => { const s = String(a.severity || '').toLowerCase(); return ['high', 'medium', 'low'].includes(s) ? s : 'medium'; };
const atk = (a, label) => `<span class="atk sev-${sevOf(a)}">${E(label || a.outcome)}</span>`;
const EMPTY_ICON = '<svg viewBox="0 0 24 24"><path d="M12 3 4 7v6c0 4.5 3.2 7.4 8 8 4.8-.6 8-3.5 8-8V7z"/><path d="m9 12 2 2 4-4"/></svg>';
const FILTERS = [['all', 'All', () => true], ['high', 'High', a => sevOf(a) === 'high'],
                 ['medium', 'Medium', a => sevOf(a) === 'medium'], ['open', 'Unacknowledged', a => !a.acknowledged]];

class App {
    constructor() {
        this.page = document.body.dataset.page || 'dashboard';
        this.socket = new SocketManager();
        this.timer = null; this.investigating = null;
        this.filter = 'all'; this.flaggedOnly = false;
        this.seen = new Set(); this.ready = false;
        setTimeout(() => { this.ready = true; }, 1500);     // rows that appear later flash once
        this.bindControls();
        this.loadReplays();
        Dashboard.subscribe(() => this.scheduleRender());
    }

    scheduleRender() {
        if (this.timer) return;
        this.timer = setTimeout(() => { this.timer = null; this.render(); }, 200);
    }
    render() {
        if (this.page === 'dashboard') this.renderRecent();
        if (this.page === 'alerts') this.renderAlerts();
        if (this.page === 'flows') this.renderFlows();
    }
    alerts() {
        return [...Dashboard.alerts.values()].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
    }
    empty(cols, title, text) {
        return `<tr><td colspan="${cols}"><div class="empty">${EMPTY_ICON}<h3>${title}</h3><p>${text}</p></div></td></tr>`;
    }

    // ---- dashboard: the five most recent alerts ----
    renderRecent() {
        const list = $('recentAlerts');
        if (!list) return;
        const rows = this.alerts().slice(0, 5);
        list.innerHTML = rows.length ? rows.map(a => `
            <li class="sev-${sevOf(a)}" data-open="${E(a.id || a.flow_id)}">
                <span class="bar"></span>
                <div><div class="what">${atk(a)}<span class="sub">${E(a.count ?? 1)} events</span></div>
                     <div class="path">${E(a.src_ip)} &rarr; ${E(a.dst_ip)}</div></div>
                <span class="when">${E(Utils.clock(a.timestamp))}</span>
            </li>`).join('')
            : `<li style="display:block;cursor:default"><div class="empty">${EMPTY_ICON}<h3>Nothing flagged</h3><p>Start a capture or replay a sample and detections appear here.</p></div></li>`;
    }

    // ---- alerts page ----
    renderAlerts() {
        const all = this.alerts();
        const bar = $('alertFilters');
        if (bar) bar.innerHTML = FILTERS.map(([key, label, fn]) =>
            `<button class="chip" data-filter="${key}" aria-pressed="${this.filter === key}">${label} <b>${all.filter(fn).length}</b></button>`).join('');
        const fn = FILTERS.find(f => f[0] === this.filter)[2];
        const rows = all.filter(fn).map(a => {
            const key = E(a.id || a.flow_id), acked = !!a.acknowledged, conf = Math.round((a.confidence || 0) * 100);
            const fresh = this.ready && !this.seen.has(key);
            this.seen.add(key);
            const port = ['neptune', 'guess_passwd'].includes(a.outcome) && a.dst_port ? `:${E(a.dst_port)}` : '';
            return `
            <tr data-key="${key}" class="${acked ? 'is-acked' : ''} ${fresh ? 'is-new' : ''}">
                <td class="mono">${E(Utils.clock(a.timestamp))}</td>
                <td>${atk(a)}${a.ioc_matches && a.ioc_matches.length ? '<span class="ioc">IOC</span>' : ''}</td>
                <td class="mono">${E(a.src_ip)}</td>
                <td class="mono">${E(a.dst_ip)}${port}</td>
                <td><span class="sevchip sev-${sevOf(a)}">${sevOf(a)}</span></td>
                <td><div style="display:flex;gap:8px;align-items:center"><span class="meter" style="width:64px"><i style="width:${conf}%"></i></span><span class="mono">${conf}%</span></div></td>
                <td class="num">${E(a.count ?? 1)}</td>
                <td class="cell-actions">
                    <button class="btn btn-sm ack-btn" data-key="${key}" ${acked ? 'disabled' : ''}>${acked ? 'Acknowledged' : 'Acknowledge'}</button>
                    <button class="btn btn-sm investigate-btn" data-key="${key}">Investigate</button>
                    <button class="btn btn-sm false-btn" data-key="${key}" title="Mark as false positive">False positive</button>
                </td>
            </tr>`;
        });
        const body = $('alertsTableBody');
        if (body) body.innerHTML = rows.length ? rows.join('')
            : this.empty(8, all.length ? 'No alerts match this filter' : 'No alerts yet', all.length ? 'Try another filter.' : 'The sensor is quiet. Detections appear here, one per attack.');
    }

    // ---- flows page ----
    renderFlows() {
        const all = [...Dashboard.flows.values()].reverse();
        const flagged = all.filter(f => f.outcome && f.outcome !== 'normal');
        const rows = (this.flaggedOnly ? flagged : all).slice(0, 200);
        const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
        set('flaggedCount', flagged.length);
        set('flowTotal', `${all.length} flows tracked`);
        const body = $('flowListBody');
        if (body) body.innerHTML = rows.length ? rows.map(f => {
            const bad = f.outcome && f.outcome !== 'normal';
            return `
            <tr data-key="${E(f.flow_id)}">
                <td class="mono">${E(Utils.clock(f.timestamp))}</td>
                <td class="mono">${E(f.src_ip)}:${E(f.src_port)}</td>
                <td class="mono">${E(f.dst_ip)}:${E(f.dst_port)}</td>
                <td><span class="tag">${E(f.protocol_type)}</span></td>
                <td>${E(f.service)}</td>
                <td><span class="tag">${E(f.flag)}</span></td>
                <td>${bad ? atk({ severity: 'high' }, f.outcome) : '<span class="atk normal">normal</span>'}</td>
                <td class="num">${E(Utils.bytes((f.src_bytes || 0) + (f.dst_bytes || 0)))}</td>
            </tr>`;
        }).join('') : this.empty(8, 'No flows yet', 'Start a capture or replay a sample and connections appear here.');
    }

    // ---- buttons ----
    bindControls() {
        const on = (id, fn) => { const el = $(id); if (el) el.addEventListener('click', fn); };
        const s = this.socket;
        on('startBtn', () => s.startIDS());
        on('stopBtn', () => s.stopIDS());
        on('replayBtn', () => { const f = $('replaySelect') && $('replaySelect').value; if (f) s.startIDS(f); });
        on('inspectorClose', () => this.closeInspector());
        on('flaggedOnly', () => { this.flaggedOnly = !this.flaggedOnly; $('flaggedOnly').setAttribute('aria-pressed', this.flaggedOnly); this.renderFlows(); });
        on('loadHistoryBtn', async () => {
            try {
                const r = await fetch('/alerts/history?limit=200');
                if (!r.ok) throw new Error(r.status);
                Dashboard.addAlerts(await r.json());
            } catch (e) { alert('Could not load alert history.'); }
        });
        on('investigateCancelBtn', () => this.closeModal());
        on('investigateSaveBtn', () => {
            if (this.investigating) s.socket.emit('investigate_alert', {
                id: this.investigating, note: $('investigationNoteInput').value.trim(),
                investigator: $('investigatorNameInput').value.trim() || null });
            this.closeModal();
        });
        document.addEventListener('keydown', e => { if (e.key === 'Escape') { this.closeInspector(); this.closeModal(); } });
        document.addEventListener('click', e => {
            const chip = e.target.closest('[data-filter]');
            if (chip) { this.filter = chip.dataset.filter; return this.renderAlerts(); }
            const btn = e.target.closest('button[data-key]');
            if (btn) return this.alertAction(btn);
            const open = e.target.closest('[data-open]');
            if (open) return this.openInspector(open.dataset.open);
            const row = e.target.closest('tr[data-key]');
            if (row) this.openInspector(row.dataset.key);
        });
    }

    alertAction(btn) {
        const key = btn.dataset.key, c = btn.classList, sock = this.socket.socket;
        if (c.contains('ack-btn')) sock.emit('ack_alert', { id: key });
        else if (c.contains('false-btn')) {
            if (confirm('Mark this alert as a false positive?'))
                sock.emit('investigate_alert', { id: key, note: 'Marked false positive', false_positive: true });
        } else if (c.contains('investigate-btn')) {
            this.investigating = key;
            $('investigationNoteInput').value = ''; $('investigatorNameInput').value = '';
            const m = $('investigateModal'); m.classList.add('open'); m.setAttribute('aria-hidden', 'false');
            $('investigationNoteInput').focus();
        }
    }
    closeModal() {
        const m = $('investigateModal');
        if (m) { m.classList.remove('open'); m.setAttribute('aria-hidden', 'true'); }
        this.investigating = null;
    }

    async loadReplays() {
        const sel = $('replaySelect');
        if (!sel) return;
        try {
            const data = await (await fetch('/api/pcaps')).json();
            for (const p of data.pcaps || []) sel.add(new Option(p.name, p.name));
        } catch (e) { /* no replay files available */ }
    }

    // ---- inspector ----
    kv(obj) {
        const rows = Object.entries(obj).filter(([, v]) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length))
            .map(([k, v]) => `<dt>${E(k.replace(/_/g, ' '))}</dt><dd>${E(v !== null && typeof v === 'object' ? JSON.stringify(v) : v)}</dd>`).join('');
        return rows ? `<dl class="kv">${rows}</dl>` : '';
    }
    openInspector(key) {
        const item = Dashboard.alerts.get(key) || Dashboard.flows.get(key);
        const panel = $('inspectorPanel');
        if (!item || !panel) return;
        const isAlert = !!item.id, list = a => `<ul>${[].concat(a).map(x => `<li>${E(x)}</li>`).join('')}</ul>`;
        let head, body;
        if (isAlert) {
            const m = item.mitre || {}, tid = m.technique_id || '';
            const mitre = tid ? `<div class="mitre"><a class="tag" target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/techniques/${E(tid.replace('.', '/'))}/">${E(tid)}</a><span class="sub">${E(m.technique_name || '')}</span></div>` : '';
            head = `<span class="sevchip sev-${sevOf(item)}">${sevOf(item)}</span> <span class="sub">${E(item.count ?? 1)} events &middot; ${E(item.flows ?? 1)} flows &middot; ${E(item.sources ?? 1)} sources</span>
                    <h3>${E(item.display_name || item.outcome)}</h3><div class="sub mono">${E(item.src_ip)} &rarr; ${E(item.dst_ip)}</div>${mitre}`;
            body = (item.reasons && item.reasons.length ? `<h4>Why it was flagged</h4>${list(item.reasons)}` : '')
                + (item.description ? `<h4>What this is</h4><p>${E(item.description)}</p>` : '')
                + (item.recommendation && item.recommendation.length ? `<h4>What to do</h4>${list(item.recommendation)}` : '')
                + (item.evidence ? `<h4>Evidence</h4>${this.kv(item.evidence)}` : '')
                + (item.ioc_matches && item.ioc_matches.length || item.names && item.names.length ? `<h4>Indicators</h4>${this.kv({ 'ioc matches': (item.ioc_matches || []).join(', '), names: (item.names || []).join(', '), 'source rdns': item.src_rdns, 'target rdns': item.dst_rdns })}` : '')
                + `<h4>Record</h4>${this.kv({ first_seen: Utils.clock(item.first_seen), last_seen: Utils.clock(item.last_seen), confidence: `${Math.round((item.confidence || 0) * 100)}%`, capture: item.capture_source, status: item.investigated ? 'investigated' : item.acknowledged ? 'acknowledged' : 'open', id: item.id })}`;
        } else {
            head = `${item.outcome && item.outcome !== 'normal' ? atk({ severity: 'high' }, item.outcome) : '<span class="atk normal">normal</span>'}
                    <h3>Flow</h3><div class="sub mono">${E(item.src_ip)}:${E(item.src_port)} &rarr; ${E(item.dst_ip)}:${E(item.dst_port)}</div>`;
            body = `<h4>Connection</h4>${this.kv({ flow_id: item.flow_id, protocol: item.protocol_type, service: item.service, state: item.flag, packets: item.packets, duration: item.duration, bytes_out: item.src_bytes, bytes_in: item.dst_bytes, confidence: item.confidence })}
                    <h4>Window features</h4>${this.kv({ count: item.count, srv_count: item.srv_count, half_open_count: item.half_open_count, half_open_rate: item.half_open_rate, serror_rate: item.serror_rate, rerror_rate: item.rerror_rate, same_srv_rate: item.same_srv_rate, diff_srv_rate: item.diff_srv_rate })}`;
        }
        $('inspectorHead').innerHTML = head;
        $('inspectorBody').innerHTML = body;
        const pcap = $('inspectorPcap');
        pcap.hidden = !isAlert;
        if (isAlert) pcap.href = Utils.withToken('/export/alert_pcap?id=' + encodeURIComponent(item.id));
        $('exportJsonBtn').onclick = () => this.downloadJson(item);
        panel.classList.add('open'); panel.setAttribute('aria-hidden', 'false');
    }
    closeInspector() {
        const panel = $('inspectorPanel');
        if (panel) { panel.classList.remove('open'); panel.setAttribute('aria-hidden', 'true'); }
    }
    downloadJson(item) {
        const url = URL.createObjectURL(new Blob([JSON.stringify(item, null, 2)], { type: 'application/json' }));
        const a = Object.assign(document.createElement('a'), { href: url, download: `${item.id || 'flow'}.json` });
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    }
}

document.addEventListener('DOMContentLoaded', () => { window.app = new App(); });
