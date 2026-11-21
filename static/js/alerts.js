// static/js/alerts.js
import { Dashboard } from './dashboard.js';
import { Utils } from './utils.js';

export class AlertManager {
    constructor() {
        this.alerts = [];
        this.setupAlertFeed();
        Dashboard.subscribe(() => this.checkForAlerts());
    }

    setupAlertFeed() {
        this.alertContainer = document.getElementById('alert-feed');
        if (!this.alertContainer) return;
    }

    checkForAlerts() {
        // Check for new attacks
        const recentAttacks = Dashboard.flows
            .filter(f => f.outcome !== 'normal')
            .slice(0, 10);

        // Update alert feed
        this.renderAlerts(recentAttacks);
    }

    renderAlerts(alerts) {
        if (!this.alertContainer) return;

        this.alertContainer.innerHTML = alerts.map(alert => `
            <div class="alert-item severity-${Utils.getSeverity(alert.outcome).toLowerCase()}">
                <span class="alert-time">${Utils.formatTimeOnly(alert.timestamp)}</span>
                <span class="alert-type">${alert.outcome}</span>
                <span class="alert-severity">${Utils.getSeverity(alert.outcome)}</span>
                <span class="alert-confidence">${Math.round((alert.confidence || 0) * 100)}%</span>
                <span class="alert-source">${alert.src_ip}</span>
            </div>
        `).join('');
    }

    showToast(message, type = 'info') {
        // Simple toast notification
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 24px;
            border-radius: 8px;
            background: ${type === 'error' ? '#ff4444' : type === 'warning' ? '#ffd700' : '#00ff88'};
            color: #000;
            font-weight: 500;
            z-index: 9999;
            animation: slideIn 0.3s ease;
        `;

        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
}