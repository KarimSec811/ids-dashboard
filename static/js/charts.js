// static/js/charts.js
import { Dashboard } from './dashboard.js';

export class ChartManager {
    constructor() {
        this.charts = {};
        this.updateScheduled = false;
        this.setupCharts();
        Dashboard.subscribe(() => this.scheduleUpdate());

        // Listen for chart updates from socket
        document.addEventListener('chart:update', () => {
            this.scheduleUpdate();
        });
    }

    scheduleUpdate() {
        if (this.updateScheduled) {
            return;
        }
        this.updateScheduled = true;
        setTimeout(() => {
            this.updateScheduled = false;
            this.updateAll();
        }, 250);
    }

    setupCharts() {

        const packetsCanvas = document.getElementById('packetsChart') || document.getElementById('trafficChart');

        if (packetsCanvas) {
            this.charts.packets = new Chart(
                packetsCanvas.getContext('2d'),
                this.getPacketsConfig()
            );
        }

        const attackTypesCanvas = document.getElementById('attackTypesChart');
        if (attackTypesCanvas) {
            this.charts.attackTypes = new Chart(
                attackTypesCanvas.getContext('2d'),
                this.getAttackTypesConfig()
            );
        }

        const protocolCanvas = document.getElementById('protocolDistribution');
        if (protocolCanvas) {
            this.charts.protocols = new Chart(
                protocolCanvas.getContext('2d'),
                this.getProtocolConfig()
            );
        }

        const topSourcesCanvas = document.getElementById('topSourceIps');
        if (topSourcesCanvas) {
            this.charts.topSources = new Chart(
                topSourcesCanvas.getContext('2d'),
                this.getTopSourcesConfig()
            );
        }

        const serviceCanvas = document.getElementById('serviceDistribution');
        if (serviceCanvas) {
            this.charts.services = new Chart(
                serviceCanvas.getContext('2d'),
                this.getServiceConfig()
            );
        }

        const timelineCanvas = document.getElementById('attackTimelineChart');
        if (timelineCanvas) {
            this.charts.timeline = new Chart(
                timelineCanvas.getContext('2d'),
                this.getTimelineConfig()
            );
        }
    }

    updateAll() {
        if (this.charts.packets) this.updatePacketsChart();
        if (this.charts.attackTypes) this.updateAttackTypesChart();
        if (this.charts.protocols) this.updateProtocolChart();
        if (this.charts.topSources) this.updateTopSourcesChart();
        if (this.charts.services) this.updateServiceChart();
        if (this.charts.timeline) this.updateTimelineChart();
    }

    updatePacketsChart() {
        const packets = this.getPacketsHistory();
        const attacks = this.getAttacksHistory();

        this.charts.packets.data.datasets[0].data = packets;
        this.charts.packets.data.datasets[1].data = attacks;
        this.charts.packets.update();
    }

    getPacketsHistory() {
        const counts = Array(60).fill(0);
        const now = Date.now();

        Dashboard.flows.forEach(flow => {
            if (flow.timestamp) {
                const t = new Date(flow.timestamp).getTime();
                const secAgo = Math.floor((now - t) / 1000);
                if (secAgo >= 0 && secAgo < 60) {
                    counts[59 - secAgo]++;
                }
            }
        });

        return counts;
    }

    getAttacksHistory() {
        const counts = Array(60).fill(0);
        const now = Date.now();

        Dashboard.flows.forEach(flow => {
            if (flow.timestamp && flow.outcome && flow.outcome !== 'normal') {
                const t = new Date(flow.timestamp).getTime();
                const secAgo = Math.floor((now - t) / 1000);
                if (secAgo >= 0 && secAgo < 60) {
                    counts[59 - secAgo]++;
                }
            }
        });

        return counts;
    }

    updateAttackTypesChart() {
        const types = Dashboard.attackStats.types;
        this.charts.attackTypes.data.labels = Object.keys(types);
        this.charts.attackTypes.data.datasets[0].data = Object.values(types);
        this.charts.attackTypes.update();
    }

    updateProtocolChart() {
        const counts = {};
        Dashboard.flows.forEach(f => {
            const proto = f.protocol_type || 'Unknown';
            counts[proto] = (counts[proto] || 0) + 1;
        });

        this.charts.protocols.data.labels = Object.keys(counts);
        this.charts.protocols.data.datasets[0].data = Object.values(counts);
        this.charts.protocols.update();
    }

    updateTopSourcesChart() {
        const sources = Dashboard.attackStats.topSources;
        this.charts.topSources.data.labels = Object.keys(sources);
        this.charts.topSources.data.datasets[0].data = Object.values(sources);
        this.charts.topSources.update();
    }

    updateServiceChart() {
        const counts = {};
        Dashboard.flows.forEach(f => {
            const service = f.service || 'Unknown';
            counts[service] = (counts[service] || 0) + 1;
        });

        const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
        const top = sorted.slice(0, 5);
        const other = sorted.slice(5).reduce((sum, [_, c]) => sum + c, 0);

        if (other > 0) top.push(['Other', other]);

        this.charts.services.data.labels = top.map(([s]) => s);
        this.charts.services.data.datasets[0].data = top.map(([_, c]) => c);
        this.charts.services.update();
    }

    updateTimelineChart() {
        const hourly = Array(24).fill(0);
        const now = new Date();
        const currentHour = now.getHours();

        Dashboard.flows.forEach(f => {
            if (f.outcome && f.outcome !== 'normal') {
                const hour = new Date(f.timestamp || now).getHours();
                hourly[hour] = (hourly[hour] || 0) + 1;
            }
        });

        // Rotate so current hour is last
        const rotated = [
            ...hourly.slice(currentHour + 1),
            ...hourly.slice(0, currentHour + 1)
        ];

        this.charts.timeline.data.datasets[0].data = rotated;
        this.charts.timeline.update();
    }

    // Chart configs (simplified - you can copy from your existing)
    getPacketsConfig() {
        return {
            type: 'line',
            data: {
                labels: Array(60).fill(''),
                datasets: [
                    {
                        label: 'Packets/sec',
                        data: Array(60).fill(0),
                        borderColor: 'rgba(54, 162, 235, 1)',
                        backgroundColor: 'rgba(54, 162, 235, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Attacks/sec',
                        data: Array(60).fill(0),
                        borderColor: 'rgba(255, 99, 132, 1)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: { display: true, text: 'Packets and attacks over time' }
                }
            }
        };
    }

    getAttackTypesConfig() {
        return {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(153, 102, 255, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: { display: true, text: 'Attack distribution' }
                }
            }
        };
    }

    getProtocolConfig() {
        return {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(201, 203, 207, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: { display: true, text: 'Protocol distribution' }
                }
            }
        };
    }

    getTopSourcesConfig() {
        return {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Flows',
                    data: [],
                    backgroundColor: 'rgba(99, 132, 255, 0.8)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { display: false },
                    title: { display: true, text: 'Top source hosts' }
                },
                scales: {
                    x: { ticks: { autoSkip: false, maxRotation: 45, minRotation: 25 } },
                    y: { beginAtZero: true }
                }
            }
        };
    }

    getServiceConfig() {
        return {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Flows',
                    data: [],
                    backgroundColor: 'rgba(255, 159, 64, 0.8)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { display: false },
                    title: { display: true, text: 'Service distribution' }
                },
                scales: {
                    x: { ticks: { autoSkip: false, maxRotation: 45, minRotation: 25 } },
                    y: { beginAtZero: true }
                }
            }
        };
    }

    getTimelineConfig() {
        return {
            type: 'line',
            data: {
                labels: Array(24).fill(''),
                datasets: [{
                    label: 'Attacks',
                    data: Array(24).fill(0),
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.3,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: { display: true, text: 'Attack timeline (hourly)' }
                }
            }
        };
    }
}