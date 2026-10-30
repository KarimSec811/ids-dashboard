// static/js/socket.js -- the Socket.IO connection and what to do with each event
import { Dashboard } from './dashboard.js';
import { Utils } from './utils.js';
import { drawChart } from './chart.js';

const $ = id => document.getElementById(id);
const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };
const setBar = (id, pct) => { const el = $(id); if (el) el.style.width = `${Math.max(0, Math.min(100, pct || 0))}%`; };

export class SocketManager {
    constructor() {
        const token = Utils.token();
        this.socket = io(token ? { auth: { token } } : {});
        const s = this.socket;

        s.on('connect', () => {
            this.setStatus('Connected', 'success');
            s.emit('request_initial_data', { page: document.body.dataset.page || 'dashboard' });
        });
        s.on('disconnect', () => this.setStatus('Disconnected', 'error'));

        s.on('flow_update', d => Dashboard.addFlows(d.flows));   // full list (flows page, on load)
        s.on('flow_batch', d => Dashboard.addFlows(d.flows));    // live changes
        s.on('alert_update', d => Dashboard.addAlerts(d.alerts));

        s.on('stats_update', d => {                              // every second
            this.showHealth(d);
            drawChart($('trafficChart'), [
                { data: d.packets_history, color: '#2563eb' },
                { data: d.attacks_history, color: '#dc2626' },
            ]);
        });
        s.on('system_health', d => this.showHealth(d));          // every 3 seconds
        s.on('status_update', d => {
            this.setStatus(d.status, d.color || 'info');
            if ('running' in d) this.setButtons(d.running);
        });
        s.on('auth_error', () => {
            this.setStatus('Access token required', 'error');
            if (!this._asked) {
                this._asked = true;
                const t = prompt('This server needs an access token (IDS_API_TOKEN):');
                if (t) { localStorage.setItem('ids_token', t); location.reload(); }
            }
        });
    }

    startIDS(pcap) { this.socket.emit('start_ids', pcap ? { pcap, speed: 10 } : {}); }
    stopIDS() { this.socket.emit('stop_ids', {}); }

    setStatus(message, type) {
        const el = $('statusMessage');
        if (el) { el.textContent = message; el.className = `status-message status-${type}`; }
        setText('statusUpdated', new Date().toLocaleTimeString());
    }

    setButtons(running) {
        for (const id of ['startBtn', 'replayBtn']) { const b = $(id); if (b) b.disabled = !!running; }
        const stop = $('stopBtn');
        if (stop) stop.disabled = !running;
    }

    showHealth(update) {
        const h = Object.assign(Dashboard.health, update);
        setText('cpuUsage', `${h.cpu_percent ?? 0}%`);
        setText('memoryUsage', `${h.memory_used_mb ?? 0} MB`);
        setText('queueValue', h.queue_length ?? 0);
        setText('uptime', h.uptime || '00:00:00');
        setBar('cpuBar', h.cpu_percent);
        setBar('memoryBar', (h.memory_used_mb / (h.memory_total_mb || 1)) * 100);
        setBar('queueBar', ((h.queue_length || 0) / 5000) * 100);
        setText('captureStatus', h.capture_status || 'STOPPED');
        setText('totalPackets', h.total_packets ?? 0);
        setText('attackPackets', h.total_attacks ?? 0);
        setText('packetRate', `${h.packets_per_sec ?? 0} pkt/s`);
        setText('packetRateLarge', h.packets_per_sec ?? 0);
        setText('attacksRateLarge', h.attacks_per_sec ?? 0);
        setText('alertCountLarge', h.unacknowledged_alerts ?? h.active_alerts ?? 0);
        if ('running' in update) this.setButtons(update.running);
    }
}
