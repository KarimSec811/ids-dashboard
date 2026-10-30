// static/js/app.js -- page controller (tables, alert buttons, inspector, replay)
import { Dashboard } from './dashboard.js';
import { SocketManager } from './socket.js';
import { Utils } from './utils.js';

const $ = id => document.getElementById(id);
const E = Utils.esc;

class App {
    constructor() {
        this.page = document.body.dataset.page || 'dashboard';
        this.socket = new SocketManager();
        this.timer = null;
        this.investigating = null;
        this.bindControls();
        this.loadReplays();
        Dashboard.subscribe(() => this.scheduleRender());
    }

    // ---- rendering (batched: at most one redraw per 200 ms) ----
    scheduleRender() {
        if (this.timer) return;
        this.timer = setTimeout(() => { this.timer = null; this.render(); }, 200);
    }

    render() {
        if (this.page === 'alerts') this.renderAlerts();
        if (this.page === 'flows') this.renderFlows();
    }

    fill(bodyId, rows, cols, emptyTitle, emptyText) {
        const body = $(bodyId);
        if (!body) return;
        body.innerHTML = rows.length ? rows.join('') :
            `<tr><td colspan="${cols}"><div class="empty-state"><h3>${emptyTitle}</h3><p>${emptyText}</p></div></td></tr>`;
    }

    renderFlows() {
        const flows = [...Dashboard.flows.values()].reverse().slice(0, 200);
        this.fill('flowListBody', flows.map(f => `
            <tr data-key="${E(f.flow_id)}" class="${f.outcome && f.outcome !== 'normal' ? 'attack-row' : ''}">
                <td>${E(f.flow_id)}</td>
                <td>${E(f.src_ip)}:${E(f.src_port)}</td>
                <td>${E(f.dst_ip)}:${E(f.dst_port)}</td>
                <td>${E(f.protocol_type)}</td>
                <td><span class="attack-badge ${E(f.outcome)}">${E(f.outcome || 'normal')}</span></td>
                <td>${Math.round((f.confidence || 0) * 100)}%</td>
            </tr>`), 6, 'Flow history is empty', 'Start capture (or replay a sample) and traffic will appear here.');
    }

    renderAlerts() {
        const alerts = [...Dashboard.alerts.values()]
            .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
        this.fill('alertsTableBody', alerts.map(a => {
            const key = E(a.id || a.flow_id), acked = !!a.acknowledged;
            return `
            <tr data-key="${key}" class="${acked ? '' : 'attack-row'}">
                <td>${E(Utils.formatTime(a.timestamp))}</td>
                <td>${E(a.src_ip)}</td>
                <td>${E(a.dst_ip)}</td>
                <td><span class="attack-badge ${E(a.outcome)}">${E(a.outcome)}</span>${a.ioc_matches && a.ioc_matches.length ? ' <span class="ioc-badge">IOC</span>' : ''}</td>
                <td class="sev-${E(a.severity)}">${E(a.severity || '-')}</td>
                <td>${Math.round((a.confidence || 0) * 100)}%</td>
                <td>${E(a.count ?? 1)}</td>
                <td style="display:flex;gap:6px;">
                    <button class="btn btn-sm btn-secondary ack-btn" data-key="${key}" ${acked ? 'disabled' : ''}>${acked ? 'Acknowledged' : 'Acknowledge'}</button>
                    <button class="btn btn-sm btn-info investigate-btn" data-key="${key}">Investigate</button>
                    <button class="btn btn-sm btn-warning false-btn" data-key="${key}">False positive</button>
                </td>
            </tr>`;
        }), 8, 'No alerts yet', 'Suspicious activity will show up here. Repeated detections are grouped into one alert.');
    }

    // ---- buttons ----
    bindControls() {
        const on = (id, fn) => { const el = $(id); if (el) el.addEventListener('click', fn); };
        const s = this.socket;
        on('startBtn', () => s.startIDS());
        on('stopBtn', () => s.stopIDS());
        on('replayBtn', () => { const f = $('replaySelect') && $('replaySelect').value; if (f) s.startIDS(f); });
        on('inspectorClose', () => this.closeInspector());
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
                id: this.investigating,
                note: $('investigationNoteInput').value.trim(),
                investigator: $('investigatorNameInput').value.trim() || null,
            });
            this.closeModal();
        });

        document.addEventListener('click', e => {
            const btn = e.target.closest('button[data-key]');
            if (btn) return this.alertAction(btn);
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
            $('investigationNoteInput').value = '';
            $('investigatorNameInput').value = '';
            const m = $('investigateModal');
            m.classList.add('open'); m.setAttribute('aria-hidden', 'false');
        }
    }

    closeModal() {
        const m = $('investigateModal');
        if (m) { m.classList.remove('open'); m.setAttribute('aria-hidden', 'true'); }
        this.investigating = null;
    }

    // ---- replay of sample captures (no capture privileges needed) ----
    async loadReplays() {
        const sel = $('replaySelect');
        if (!sel) return;
        try {
            const data = await (await fetch('/api/pcaps')).json();
            for (const p of data.pcaps || []) sel.add(new Option(p.name, p.name));
        } catch (e) { /* no replay files available */ }
    }

    // ---- inspector ----
    openInspector(key) {
        const item = Dashboard.alerts.get(key) || Dashboard.flows.get(key);
        const panel = $('inspectorPanel'), body = $('inspectorBody');
        if (!item || !panel || !body) return;
        $('inspectorTitle').textContent = item.id ? `Alert: ${item.outcome}` : 'Flow';
        const why = item.reasons && item.reasons.length
            ? `<h4>Why it was flagged</h4><ul>${item.reasons.map(r => `<li>${E(r)}</li>`).join('')}</ul>` : '';
        const pcap = item.id
            ? `<p><a class="btn btn-sm btn-secondary" href="${E(Utils.withToken('/export/alert_pcap?id=' + encodeURIComponent(item.id)))}">Download evidence PCAP</a></p>` : '';
        const rows = Object.entries(item).filter(([k]) => k !== 'reasons').map(([k, v]) => {
            const shown = /timestamp|first_seen|last_seen/.test(k) ? Utils.formatTime(v)
                : (v !== null && typeof v === 'object') ? JSON.stringify(v) : v;
            return `<dt>${E(k)}</dt><dd>${E(shown)}</dd>`;
        }).join('');
        body.innerHTML = `${why}${pcap}<dl>${rows}</dl>`;
        $('exportJsonBtn').onclick = () => this.downloadJson(item);
        panel.classList.add('open');
        panel.setAttribute('aria-hidden', 'false');
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
