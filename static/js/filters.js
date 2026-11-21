// static/js/filters.js
import { Dashboard } from './dashboard.js';

export class FilterManager {
    constructor() {
        this.setupProtocolFilter();
        this.setupAttackFilter();
        this.setupSeverityFilter();
    }

    setupProtocolFilter() {
        const select = document.getElementById('protocol-filter');
        if (!select) return;

        select.addEventListener('change', () => {
            Dashboard.ui.protocolFilter = select.value;
            Dashboard.notify();
        });
    }

    setupAttackFilter() {
        const select = document.getElementById('attack-filter');
        if (!select) return;

        // Populate with attack types from Dashboard
        this.updateAttackOptions();

        select.addEventListener('change', () => {
            Dashboard.ui.attackFilter = select.value;
            Dashboard.notify();
        });

        // Update options when flows change
        Dashboard.subscribe(() => this.updateAttackOptions());
    }

    updateAttackOptions() {
        const select = document.getElementById('attack-filter');
        if (!select) return;

        const types = new Set();
        Dashboard.flows.forEach(f => {
            if (f.outcome && f.outcome !== 'normal') {
                types.add(f.outcome);
            }
        });

        // Keep "all" option
        const currentValue = select.value;
        select.innerHTML = '<option value="all">Все атаки</option>';

        types.forEach(type => {
            const option = document.createElement('option');
            option.value = type;
            option.textContent = type;
            select.appendChild(option);
        });

        if (currentValue && types.has(currentValue)) {
            select.value = currentValue;
        }
    }

    setupSeverityFilter() {
        // Similar to above
    }
}