// Charts poll /dashboard/api/timeline and update in place; re-creating them on every refresh would flicker.
window.AIGateCharts = (function () {
  const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  function baseOptions() {
    return {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', align: 'start', labels: { color: css('--fg'), boxWidth: 12, boxHeight: 12 } },
        tooltip: { backgroundColor: css('--surface'), titleColor: css('--fg'), bodyColor: css('--fg'),
                   borderColor: css('--line'), borderWidth: 1 }
      },
      scales: {
        x: { ticks: { color: css('--muted'), maxRotation: 0, autoSkipPadding: 16 }, grid: { display: false },
             border: { color: css('--line') } },
        y: { beginAtZero: true, ticks: { color: css('--muted'), precision: 0 }, grid: { color: css('--grid') },
             border: { display: false } }
      }
    };
  }

  const label = iso => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  function poll(chart, fill) {
    const load = () => fetch('/dashboard/api/timeline').then(r => r.json()).then(rows => {
      chart.data.labels = rows.map(r => label(r.start));
      fill(chart, rows);
      chart.update('none');
    }).catch(() => {});
    load();
    setInterval(load, 5000);
  }

  function decisions(id) {
    const bar = (lbl, color) => ({ label: lbl, data: [], backgroundColor: color, borderColor: css('--surface'),
      borderWidth: { top: 2 }, borderSkipped: 'bottom', borderRadius: 4, barPercentage: 0.7, categoryPercentage: 0.9 });
    const options = baseOptions();
    options.scales.x.stacked = true;
    options.scales.y.stacked = true;
    options.scales.y.title = { display: true, text: 'requests', color: css('--muted') };
    const chart = new Chart(document.getElementById(id), {
      type: 'bar',
      data: { labels: [], datasets: [bar('Allowed', css('--chart-allow')), bar('Redacted', css('--chart-redact')),
                                        bar('Blocked', css('--chart-block'))] },
      options
    });
    poll(chart, (c, rows) => {
      c.data.datasets[0].data = rows.map(r => r.allowed);
      c.data.datasets[1].data = rows.map(r => r.redacted);
      c.data.datasets[2].data = rows.map(r => r.blocked);
    });
  }

  function tokens(id) {
    const options = baseOptions();
    options.plugins.legend.display = false;
    options.scales.y.title = { display: true, text: 'tokens', color: css('--muted') };
    const chart = new Chart(document.getElementById(id), {
      type: 'line',
      data: { labels: [], datasets: [{ label: 'Tokens', data: [], borderColor: css('--accent'), borderWidth: 2,
        backgroundColor: css('--accent-soft'), fill: true, pointRadius: 0, pointHoverRadius: 5, tension: 0 }] },
      options
    });
    poll(chart, (c, rows) => { c.data.datasets[0].data = rows.map(r => r.tokens); });
  }

  return { decisions, tokens };
})();
