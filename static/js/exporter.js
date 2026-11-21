// static/js/exporter.js
import { Dashboard } from './dashboard.js';

export class ExportManager {
    exportJSON(flows) {
        const data = {
            exported_at: new Date().toISOString(),
            total_flows: flows.length,
            attacks: flows.filter(f => f.outcome !== 'normal').length,
            flows: flows
        };

        const json = JSON.stringify(data, null, 2);
        this.download(json, `ids-export-${Date.now()}.json`, 'application/json');
    }

    exportCSV(flows) {
        if (flows.length === 0) {
            alert('Нет данных для экспорта');
            return;
        }

        const headers = Object.keys(flows[0]);
        const rows = flows.map(f => headers.map(h => f[h] || '').join(','));
        const csv = [headers.join(','), ...rows].join('\n');

        this.download(csv, `ids-export-${Date.now()}.csv`, 'text/csv');
    }

    download(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
}