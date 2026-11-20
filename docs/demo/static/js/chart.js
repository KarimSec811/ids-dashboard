// static/js/chart.js -- the live traffic trace: canvas, no library, follows the colour scheme
const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const state = new WeakMap();

function niceMax(v) {
    if (v <= 10) return 10;
    const p = 10 ** Math.floor(Math.log10(v)), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}
const fmt = v => (v >= 1000 ? `${+(v / 1000).toFixed(1)}k` : `${v}`);

function paint(canvas, hover) {
    const st = state.get(canvas), g = canvas.getContext('2d');
    const [traffic, flagged] = st.series.map(s => s.data || []);
    const n = traffic.length, dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 800, h = canvas.clientHeight || 250;
    canvas.width = w * dpr; canvas.height = h * dpr;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    const L = 42, R = 16, T = 12, B = 26, iw = w - L - R, ih = h - T - B;
    const max = niceMax(Math.max(1, ...traffic, ...flagged));
    const X = i => L + (i / (n - 1)) * iw, Y = v => T + ih - (v / max) * ih;
    const signal = css('--signal'), alarm = css('--alarm'), line = css('--line-2'), muted = css('--faint');

    g.font = '11px Inter, system-ui, sans-serif';
    g.textBaseline = 'middle';
    for (let k = 0; k <= 4; k++) {                           // grid + y labels
        const y = T + (ih * k) / 4;
        g.strokeStyle = line; g.lineWidth = 1;
        g.beginPath(); g.moveTo(L, y + .5); g.lineTo(w - R, y + .5); g.stroke();
        g.fillStyle = muted; g.textAlign = 'right';
        g.fillText(fmt(Math.round(max * (1 - k / 4))), L - 8, y);
    }
    g.textAlign = 'center'; g.textBaseline = 'alphabetic';    // x labels
    for (const s of [60, 45, 30, 15, 0]) g.fillText(s ? `-${s}s` : 'now', X((n - 1) * (1 - s / 60)), h - 6);

    const area = (data, color, alpha) => {
        const grad = g.createLinearGradient(0, T, 0, T + ih);
        grad.addColorStop(0, color + alpha); grad.addColorStop(1, color + '00');
        g.beginPath(); g.moveTo(X(0), Y(0));
        data.forEach((v, i) => g.lineTo(X(i), Y(v)));
        g.lineTo(X(n - 1), Y(0)); g.closePath(); g.fillStyle = grad; g.fill();
        g.beginPath(); data.forEach((v, i) => (i ? g.lineTo(X(i), Y(v)) : g.moveTo(X(i), Y(v))));
        g.strokeStyle = color; g.lineWidth = 2; g.lineJoin = 'round'; g.stroke();
    };
    area(traffic, signal, '55');
    area(flagged, alarm, '66');

    const last = n - 1;                                       // live end marker
    g.fillStyle = signal; g.beginPath(); g.arc(X(last), Y(traffic[last]), 4, 0, 7); g.fill();
    g.strokeStyle = css('--paper'); g.lineWidth = 2; g.stroke();

    const tip = document.getElementById('chartTip');
    if (hover == null) { if (tip) tip.hidden = true; return; }
    const hx = X(hover);                                      // hover crosshair + tooltip
    g.strokeStyle = muted; g.setLineDash([3, 3]); g.beginPath(); g.moveTo(hx, T); g.lineTo(hx, T + ih); g.stroke(); g.setLineDash([]);
    if (tip) {
        tip.hidden = false;
        tip.innerHTML = `<b>${traffic[hover]}</b> packets &middot; <b style="color:#ff9d8c">${flagged[hover]}</b> flagged<br><span style="opacity:.7">${n - 1 - hover ? `${n - 1 - hover}s ago` : 'now'}</span>`;
        tip.style.left = `${hx + canvas.offsetLeft}px`;
        tip.style.top = `${Y(Math.max(traffic[hover], flagged[hover])) + canvas.offsetTop}px`;
    }
}

export function drawChart(canvas, series) {
    if (!canvas || !series || !series.length || !(series[0].data || []).length || !canvas.getContext || !canvas.getContext('2d')) return;
    const first = !state.has(canvas);
    state.set(canvas, { series, hover: state.get(canvas)?.hover ?? null });
    if (first) {
        canvas.addEventListener('mousemove', e => {
            const st = state.get(canvas), n = st.series[0].data.length, r = canvas.getBoundingClientRect();
            st.hover = Math.max(0, Math.min(n - 1, Math.round(((e.clientX - r.left - 42) / (r.width - 58)) * (n - 1))));
            paint(canvas, st.hover);
        });
        canvas.addEventListener('mouseleave', () => { state.get(canvas).hover = null; paint(canvas, null); });
    }
    paint(canvas, state.get(canvas).hover);
}
