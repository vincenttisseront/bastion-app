(function () {
  var STATUS_BADGE = {
    ok: 'badge-ok',
    warn: 'badge-warn',
    error: 'badge-err',
    unknown: 'badge-muted'
  };

  function formatRelative(iso) {
    if (!iso) return '';
    var then = new Date(iso).getTime();
    if (Number.isNaN(then)) return '';
    var diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
    if (diffSec < 60) return 'il y a ' + diffSec + ' s';
    var diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return 'il y a ' + diffMin + ' min';
    var diffHr = Math.floor(diffMin / 60);
    return 'il y a ' + diffHr + ' h';
  }

  function setBadge(el, status) {
    if (!el) return;
    var key = status || 'unknown';
    el.textContent = key.toUpperCase();
    el.className = 'badge probe-status-badge ' + (STATUS_BADGE[key] || STATUS_BADGE.unknown);
  }

  function updateRow(row, payload) {
    if (!row || !payload) return;
    var status = payload.status || 'unknown';
    setBadge(row.querySelector('[data-field="status"]'), status);

    var httpCell = row.querySelector('[data-field="http_code"]');
    if (httpCell) httpCell.textContent = payload.http_code != null ? String(payload.http_code) : '—';

    var latencyCell = row.querySelector('[data-field="latency_ms"]');
    if (latencyCell) {
      latencyCell.textContent = payload.latency_ms != null ? payload.latency_ms + ' ms' : '—';
    }

    var aged = row.querySelector('[data-field="probed_at"]');
    if (aged) {
      if (payload.probed_at) {
        aged.hidden = false;
        var span = aged.querySelector('[data-iso]') || aged;
        if (span.dataset) span.dataset.iso = payload.probed_at;
        aged.textContent = formatRelative(payload.probed_at);
      } else {
        aged.hidden = true;
      }
    }

    var errEl = row.querySelector('[data-field="error"]');
    if (errEl) {
      if (payload.error) {
        errEl.hidden = false;
        errEl.textContent = payload.error;
      } else {
        errEl.hidden = true;
        errEl.textContent = '';
      }
    }
  }

  function updateMetrics(statusCounts, healthScore) {
    if (statusCounts) {
      document.querySelectorAll('[data-count]').forEach(function (el) {
        var key = el.getAttribute('data-count');
        if (key && statusCounts[key] != null) el.textContent = statusCounts[key];
      });
    }
    var scoreEl = document.getElementById('health-score');
    if (scoreEl && healthScore != null) scoreEl.textContent = healthScore + '%';
  }

  function recalcMetricsFromDom() {
    var counts = { ok: 0, warn: 0, error: 0, unknown: 0 };
    document.querySelectorAll('[data-probe-row]').forEach(function (row) {
      var badge = row.querySelector('[data-field="status"]');
      if (!badge) return;
      var status = (badge.textContent || 'unknown').trim().toLowerCase();
      if (!counts[status]) status = 'unknown';
      counts[status] += 1;
    });
    var total = counts.ok + counts.warn + counts.error + counts.unknown;
    var score = total ? Math.round((counts.ok / total) * 100) : 100;
    updateMetrics(counts, score);
  }

  function setButtonLoading(btn, loading) {
    if (!btn) return;
    btn.disabled = loading;
    btn.dataset.originalLabel = btn.dataset.originalLabel || btn.textContent;
    btn.textContent = loading ? 'Test…' : btn.dataset.originalLabel;
  }

  async function probeApp(appId, btn) {
    setButtonLoading(btn, true);
    try {
      var resp = await fetch('/admin/health/probe/' + appId, { method: 'POST', headers: { Accept: 'application/json' } });
      if (!resp.ok) throw new Error('Probe failed');
      var payload = await resp.json();
      var row = document.querySelector('[data-probe-row][data-app-id="' + appId + '"]');
      updateRow(row, payload);
      recalcMetricsFromDom();
    } catch (err) {
      alert('Échec de la sonde : ' + err.message);
    } finally {
      setButtonLoading(btn, false);
    }
  }

  async function probeAll(btn) {
    setButtonLoading(btn, true);
    try {
      var resp = await fetch('/admin/health/probe-all', { method: 'POST', headers: { Accept: 'application/json' } });
      if (!resp.ok) throw new Error('Probe-all failed');
      var data = await resp.json();
      (data.results || []).forEach(function (payload) {
        var row = document.querySelector('[data-probe-row][data-app-id="' + payload.app_id + '"]');
        updateRow(row, payload);
      });
      updateMetrics(data.status_counts, data.health_score);
    } catch (err) {
      alert('Échec du test global : ' + err.message);
    } finally {
      setButtonLoading(btn, false);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.probe-aged [data-iso]').forEach(function (el) {
      var parent = el.closest('.probe-aged');
      if (parent) parent.textContent = formatRelative(el.dataset.iso);
    });

    document.querySelectorAll('.probe-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        probeApp(btn.dataset.appId, btn);
      });
    });

    var allBtn = document.getElementById('probe-all-btn');
    if (allBtn) {
      allBtn.addEventListener('click', function () { probeAll(allBtn); });
    }
  });
})();
