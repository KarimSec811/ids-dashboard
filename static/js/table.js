// static/js/table.js
import { Dashboard } from './dashboard.js';
import { Utils } from './utils.js';

export class TableRenderer {
    constructor(tableBody, tableHead, loader) {
        this.tableBody = tableBody;
        this.tableHead = tableHead;
        this.loader = loader;
        
        this.columns = [
            { key: 'flow_id', label: 'ID потока', width: '120px' },
            { key: 'src_ip', label: 'IP источника', width: '140px' },
            { key: 'dst_ip', label: 'IP назначения', width: '140px' },
            { key: 'protocol_type', label: 'Протокол', width: '100px' },
            { key: 'service', label: 'Сервис', width: '100px' },
            { key: 'src_port', label: 'Порт ист.', width: '80px' },
            { key: 'dst_port', label: 'Порт назн.', width: '80px' },
            { key: 'outcome', label: 'Результат', width: '120px' },
            { key: 'timestamp', label: 'Время', width: '160px' }
        ];
        
        // Subscribe to Dashboard changes
        Dashboard.subscribe(() => this.render());
        
        this.setupSorting();
        this.render();
    }
    
    setupSorting() {
        this.tableHead.addEventListener('click', (e) => {
            const th = e.target.closest('th');
            if (!th || !th.dataset.sort) return;
            
            const column = th.dataset.sort;
            if (Dashboard.ui.sortColumn === column) {
                Dashboard.ui.sortDirection = 
                    Dashboard.ui.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                Dashboard.ui.sortColumn = column;
                Dashboard.ui.sortDirection = 'desc';
            }
            
            Dashboard.notify();
        });
    }
    
    render() {
        this.showLoader();
        
        // Use requestAnimationFrame for smooth rendering
        requestAnimationFrame(() => {
            this.renderHeader();
            this.renderBody();
            this.hideLoader();
        });
    }
    
    renderHeader() {
        this.tableHead.innerHTML = `
            <tr>
                ${this.columns.map(col => `
                    <th data-sort="${col.key}" style="width: ${col.width}">
                        ${col.label}
                        <i class="fas fa-sort"></i>
                    </th>
                `).join('')}
            </tr>
        `;
        
        // Update sort indicators
        const currentTh = this.tableHead.querySelector(
            `th[data-sort="${Dashboard.ui.sortColumn}"]`
        );
        if (currentTh) {
            const icon = currentTh.querySelector('i');
            if (icon) {
                icon.className = Dashboard.ui.sortDirection === 'asc' 
                    ? 'fas fa-sort-up' 
                    : 'fas fa-sort-down';
            }
        }
    }
    
    renderBody() {
        const flows = Dashboard.filteredFlows;
        
        if (flows.length === 0) {
            this.tableBody.innerHTML = `
                <tr>
                    <td colspan="${this.columns.length}" style="text-align: center; padding: 40px;">
                        <i class="fas fa-inbox" style="font-size: 24px; opacity: 0.3;"></i>
                        <p style="margin-top: 10px; opacity: 0.5;">Нет данных для отображения</p>
                    </td>
                </tr>
            `;
            return;
        }
        
        this.tableBody.innerHTML = flows.map(flow => this.createRow(flow)).join('');
    }
    
    createRow(flow) {
        const confidence = Math.round((flow.confidence || 0) * 100);
        const isAttack = flow.outcome && flow.outcome !== 'normal';
        
        return `
            <tr class="flow-row ${isAttack ? 'attack-row' : ''}" 
                data-id="${flow.flow_id}"
                onclick="window.selectFlow && window.selectFlow('${flow.flow_id}')"
                ondblclick="window.selectFlow && window.selectFlow('${flow.flow_id}')">
                <td>${flow.flow_id || '-'}</td>
                <td>${Utils.formatTime(flow.timestamp)}</td>
                <td>${flow.src_ip || '-'}</td>
                <td>${flow.dst_ip || '-'}</td>
                <td><span class="protocol protocol-${(flow.protocol_type || 'unknown').toLowerCase()}">${flow.protocol_type || '-'}</span></td>
                <td>${flow.service || '-'}</td>
                <td>
                    <span class="attack-badge attack-${flow.outcome || 'normal'}">
                        ${flow.outcome || 'normal'}
                    </span>
                </td>
                <td>
                    <div class="confidence-wrapper">
                        <div class="confidence-bar">
                            <div class="confidence-fill ${(flow.confidence || 0) > 0.7 ? 'high' : (flow.confidence || 0) > 0.4 ? 'medium' : 'low'}"
                                style="width: ${Math.round((flow.confidence || 0) * 100)}%"></div>
                        </div>
                        <span class="confidence-text">${Math.round((flow.confidence || 0) * 100)}%</span>
                    </div>
                </td>
                <td>${flow.duration ? flow.duration.toFixed(2) + 's' : '-'}</td>
                <td>${(flow.src_bytes || 0) + (flow.dst_bytes || 0)}</td>
            </tr>
        `;
    }
    
    showLoader() {
        if (this.loader) this.loader.style.display = 'block';
    }
    
    hideLoader() {
        if (this.loader) this.loader.style.display = 'none';
    }
}