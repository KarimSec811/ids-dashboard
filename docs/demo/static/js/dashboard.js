// static/js/dashboard.js -- the one place the UI keeps its data
// Flows are keyed by flow_id, alerts by id. Map order = most recently updated last.
export const Dashboard = {
    flows: new Map(),
    alerts: new Map(),
    health: {},
    subscribers: [],

    subscribe(fn) { this.subscribers.push(fn); },
    notify() { this.subscribers.forEach(fn => fn(this)); },

    _merge(map, items, keyOf, max) {
        for (const item of items || []) {
            const key = keyOf(item);
            if (!key) continue;
            const merged = { ...(map.get(key) || {}), ...item };
            map.delete(key);          // re-insert so the newest update is last
            map.set(key, merged);
        }
        while (map.size > max) map.delete(map.keys().next().value);
        this.notify();
    },
    addFlows(items) { this._merge(this.flows, items, f => f.flow_id, 500); },
    addAlerts(items) { this._merge(this.alerts, items, a => a.id || a.flow_id, 200); },
};
