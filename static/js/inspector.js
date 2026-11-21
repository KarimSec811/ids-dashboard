// static/js/inspector.js
import { Dashboard } from './dashboard.js';
import { Utils } from './utils.js';

export class InspectorManager {
    constructor() {
        this.panel = document.getElementById('inspector-panel');
        this.content = document.getElementById('inspector-content');
        this.selectedFlow = null;
        this.setupCloseButton();
    }
    
    setupCloseButton() {
        const closeBtn = document.getElementById('close-inspector');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideInspector());
        }
    }
    
    showInspector(flow) {
        this.selectedFlow = flow;
        if (!this.panel) return;
        
        this.content.innerHTML = this.renderInspector(flow);
        this.panel.classList.add('open');
        
        // Update URL hash for bookmarking
        history.pushState({ flowId: flow.flow_id }, '', `#flow-${flow.flow_id}`);
    }
    
    hideInspector() {
        if (this.panel) {
            this.panel.classList.remove('open');
        }
    }
    
    selectFlow(flow) {
        // Highlight row in table
        // This will be handled by the table module
    }
    
    renderInspector(flow) {
        const confidence = Math.round((flow.confidence || 0) * 100);
        const severity = Utils.getSeverity(flow.outcome);
        const severityColor = Utils.getSeverityColor(severity);
        
        return `
            <div class="inspector-header">
                <h3>Детали потока</h3>
                <button id="close-inspector-btn" class="close-btn">×</button>
            </div>
            <div class="inspector-body">
                <!-- Confidence Gauge -->
                <div class="inspector-confidence">
                    <div class="confidence-gauge" style="
                        background: conic-gradient(
                            ${severityColor} ${confidence}%, 
                            #2a2a2a ${confidence}%
                        );
                    ">
                        <span class="confidence-value">${confidence}%</span>
                    </div>
                    <span class="confidence-label">Доверие</span>
                </div>
                
                <!-- Basic Info -->
                <div class="inspector-section">
                    <h4>Основная информация</h4>
                    <div class="inspector-grid">
                        <div><label>Flow ID</label><span>${flow.flow_id || '-'}</span></div>
                        <div><label>Время</label><span>${Utils.formatTime(flow.timestamp)}</span></div>
                        <div><label>Протокол</label><span>${flow.protocol_type || '-'}</span></div>
                        <div><label>Сервис</label><span>${flow.service || '-'}</span></div>
                        <div><label>Результат</label><span class="attack-badge attack-${flow.outcome}">${flow.outcome || 'normal'}</span></div>
                        <div><label>Статус</label><span>${flow.status || 'Активен'}</span></div>
                    </div>
                </div>
                
                <!-- Source/Destination -->
                <div class="inspector-section">
                    <h4>Источник → Назначение</h4>
                    <div class="inspector-grid">
                        <div><label>Источник</label><span>${flow.src_ip}:${flow.src_port || '?'}</span></div>
                        <div><label>Назначение</label><span>${flow.dst_ip}:${flow.dst_port || '?'}</span></div>
                    </div>
                </div>
                
                <!-- MITRE ATT&CK -->
                <div class="inspector-section">
                    <h4>MITRE ATT&CK</h4>
                    <div class="mitre-tags">
                        ${this.getMITREMapping(flow.outcome).map(technique => `
                            <span class="mitre-tag">${technique}</span>
                        `).join('')}
                    </div>
                </div>
                
                <!-- Feature Vector (if available) -->
                ${this.renderFeatures(flow)}
                
                <!-- JSON Export -->
                <div class="inspector-section">
                    <h4>Raw JSON</h4>
                    <button class="btn btn-sm btn-secondary" onclick="navigator.clipboard.writeText(JSON.stringify(${JSON.stringify(flow)}, null, 2))">
                        <i class="fas fa-copy"></i> Копировать
                    </button>
                    <pre class="json-view">${JSON.stringify(flow, null, 2)}</pre>
                </div>
            </div>
        `;
    }
    
    getMITREMapping(attackType) {
        const mapping = {
            'neptune': ['T1498', 'T1499'],
            'portsweep': ['T1046'],
            'ipsweep': ['T1046'],
            'smurf': ['T1498', 'T1499'],
            'satan': ['T1046', 'T1595'],
            'normal': ['N/A']
        };
        return mapping[attackType] || ['T1595', 'T1046'];
    }
    
    renderFeatures(flow) {
        // Check for NSL-KDD features
        const features = [
            'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count'
        ];
        
        const hasFeatures = features.some(f => flow[f] !== undefined);
        if (!hasFeatures) return '';
        
        return `
            <div class="inspector-section">
                <h4>NSL-KDD Особенности</h4>
                <div class="inspector-grid">
                    ${features.map(f => {
                        const value = flow[f];
                        if (value === undefined) return '';
                        return `
                            <div>
                                <label>${f}</label>
                                <span>${typeof value === 'number' ? value.toFixed(3) : value}</span>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }
}