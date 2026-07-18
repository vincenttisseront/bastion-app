(function () {
  'use strict';

  var POLL_MS = 15000;
  var isAdmin = window.__SESSIONS_IS_ADMIN__ === true;

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function postAction(url, confirmMsg) {
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCsrfToken(),
        'Content-Type': 'application/json',
      },
      credentials: 'same-origin',
    })
      .then(function (r) {
        if (!r.ok) throw new Error('Action failed');
        return r.json();
      })
      .then(function () {
        window.location.reload();
      })
      .catch(function () {
        alert('Erreur lors de l\'exécution de l\'action.');
      });
  }

  window.isolateSession = function (sessionId) {
    postAction('/admin/sessions/' + encodeURIComponent(sessionId) + '/isolate', 'Isoler cette session ?');
  };

  window.rotateKeys = function (sessionId) {
    postAction('/admin/sessions/' + encodeURIComponent(sessionId) + '/rotate-keys', 'Lancer la rotation des clés pour cette session ?');
  };

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function kindLabel(kind) {
    return kind === 'app' ? 'Application' : 'Utilisateur';
  }

  function renderRow(s) {
    var initial = (s.user && s.user[0] ? s.user[0] : '?').toUpperCase();
    var statusClass = s.status === 'active' ? 'ok' : 'warn';
    var kindClass = s.kind === 'user' ? 'info' : 'ok';
    var liveDot =
      s.status === 'active'
        ? '<span class="live-dot" style="width:6px;height:6px;"></span> '
        : '';
    var actions = '';
    if (isAdmin) {
      actions =
        '<td><div class="session-actions">' +
        '<button type="button" class="btn-isolate" onclick="isolateSession(\'' +
        escapeHtml(s.id) +
        '\')">Isoler</button>' +
        '<button type="button" class="btn-rotate" onclick="rotateKeys(\'' +
        escapeHtml(s.id) +
        '\')">Rotation</button>' +
        '</div></td>';
    }
    return (
      '<tr data-searchable data-kind="' +
      escapeHtml(s.kind) +
      '" data-session-id="' +
      escapeHtml(s.id) +
      '">' +
      '<td><div style="display:flex;align-items:center;gap:var(--sp-2);">' +
      '<div class="user-avatar" style="width:28px;height:28px;font-size:10px;">' +
      escapeHtml(initial) +
      '</div><div><div style="font-weight:600;">' +
      escapeHtml(s.user) +
      '</div><div class="mono">' +
      escapeHtml(s.realm) +
      '</div></div></div></td>' +
      '<td><span class="badge badge-' +
      kindClass +
      '">' +
      kindLabel(s.kind) +
      '</span></td>' +
      '<td><span class="proto-tag ' +
      escapeHtml(String(s.protocol || '').toLowerCase()) +
      '">' +
      escapeHtml(s.protocol) +
      '</span></td>' +
      '<td class="mono">' +
      escapeHtml(s.target) +
      '</td>' +
      '<td class="mono">' +
      escapeHtml(s.source_ip) +
      '</td>' +
      '<td class="mono session-duration">' +
      escapeHtml(s.duration) +
      '</td>' +
      '<td><span class="badge badge-' +
      statusClass +
      '">' +
      liveDot +
      escapeHtml(String(s.status || '').toUpperCase()) +
      '</span></td>' +
      actions +
      '</tr>'
    );
  }

  function emptyRow() {
    var cols = isAdmin ? 8 : 7;
    return (
      '<tr class="sessions-empty-row"><td colspan="' +
      cols +
      '"><div class="empty-state">' +
      '<div class="empty-title">Aucune session active</div>' +
      '<div class="empty-desc">Les connexions portail et les ouvertures d’applications apparaîtront ici.</div>' +
      '</div></td></tr>'
    );
  }

  function updateCounts(counts) {
    if (!counts) return;
    document.querySelectorAll('.session-kind-tab').forEach(function (tab) {
      var k = tab.getAttribute('data-kind');
      var el = tab.querySelector('.session-kind-count');
      if (!el) return;
      if (k === 'all') el.textContent = counts.all != null ? counts.all : '0';
      else if (k === 'user') el.textContent = counts.user != null ? counts.user : '0';
      else if (k === 'app') el.textContent = counts.app != null ? counts.app : '0';
    });
  }

  function refreshSessions() {
    var page = document.getElementById('sessions-page');
    var tbody = document.getElementById('sessions-tbody');
    if (!page || !tbody) return;
    var kind = page.getAttribute('data-kind') || 'all';
    var url = '/api/sessions';
    if (kind === 'user' || kind === 'app') url += '?kind=' + encodeURIComponent(kind);

    fetch(url, { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('poll failed');
        return r.json();
      })
      .then(function (data) {
        var sessions = data.sessions || [];
        var countEl = document.getElementById('sessions-count');
        if (countEl) countEl.textContent = String(sessions.length);
        updateCounts(data.counts);
        if (!sessions.length) {
          tbody.innerHTML = emptyRow();
          return;
        }
        tbody.innerHTML = sessions.map(renderRow).join('');
      })
      .catch(function () {
        /* silent — keep last render */
      });
  }

  if (document.getElementById('sessions-page')) {
    setInterval(refreshSessions, POLL_MS);
  }
})();
