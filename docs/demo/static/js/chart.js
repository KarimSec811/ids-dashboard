// static/js/chart.js -- tiny line chart, no library needed
export function drawChart(canvas, series) {
    if (!canvas || !series || !series.length) return;
    const g = canvas.getContext && canvas.getContext('2d');
    if (!g) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 600, h = canvas.clientHeight || 160;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    g.scale(dpr, dpr);
    g.clearRect(0, 0, w, h);
    const max = Math.max(1, ...series.flatMap(s => s.data || []));
    g.strokeStyle = 'rgba(128,128,128,.3)';
    g.beginPath(); g.moveTo(0, h - .5); g.lineTo(w, h - .5); g.stroke();
    g.fillStyle = 'rgba(128,128,128,.9)';
    g.font = '11px sans-serif';
    g.fillText(`${max} /s`, 4, 12);
    for (const s of series) {
        const d = s.data || [];
        if (d.length < 2) continue;
        g.strokeStyle = s.color;
        g.lineWidth = 2;
        g.beginPath();
        d.forEach((v, i) => {
            const x = (i / (d.length - 1)) * w, y = h - 4 - (v / max) * (h - 20);
            i ? g.lineTo(x, y) : g.moveTo(x, y);
        });
        g.stroke();
    }
}
