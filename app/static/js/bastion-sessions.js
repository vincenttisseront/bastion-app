(function () {
  'use strict';

  var POLL_MS = 15000;
  var isAdmin = window.__SESSIONS_IS_ADMIN__ === true;

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  async function postAction(url, confirmMsg) {
    if (confirmMsg) {
      var ok = await window.bastionConfirm({
        title: 'Confirmer l\'action',
        message: confirmMsg,
        confirmLabel: 'Confirmer',
        danger: true,
      });
      if (!ok) return;
    }
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
        window.bastionAlert({
          title: 'Erreur',
          message: 'Erreur lors de l\'exécution de l\'action.',
        });
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

  function cookieTitle(s) {
    var parts = [];
    if (s.cookies_issued_at) parts.push('émis ' + s.cookies_issued_at);
    if (s.crushauth_age) parts.push('CrushAuth ' + s.crushauth_age);
    if (s.credential_source) parts.push(s.credential_source);
    if (s.robotic_username) parts.push(s.robotic_username);
    return parts.join(' · ');
  }

  function renderChild(s) {
    var statusClass = s.status === 'active' ? 'ok' : 'warn';
    var kindClass = s.kind === 'user' ? 'info' : 'ok';
    var cookieClass = s.cookies_ok ? 'ok' : 'warn';
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
      '<tr class="session-child-row" data-searchable data-kind="' +
      escapeHtml(s.kind) +
      '" data-session-id="' +
      escapeHtml(s.id) +
      '" data-user-email="' +
      escapeHtml(s.user_email) +
      '">' +
      '<td class="session-child-indent mono">↳</td>' +
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
      '<td><span class="session-cookies badge badge-' +
      cookieClass +
      '" title="' +
      escapeHtml(cookieTitle(s)) +
      '">' +
      escapeHtml(s.cookies_label || '—') +
      '</span></td>' +
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

  function renderGroup(g) {
    var cols = isAdmin ? 9 : 8;
    var initial = (g.user && g.user[0] ? g.user[0] : '?').toUpperCase();
    var statusClass = g.status === 'active' ? 'ok' : 'warn';
    var head =
      '<tr class="session-group-row" data-searchable data-user-email="' +
      escapeHtml(g.user_email) +
      '"><td colspan="' +
      cols +
      '"><div class="session-group-head">' +
      '<div class="session-group-user">' +
      '<div class="user-avatar" style="width:28px;height:28px;font-size:10px;">' +
      escapeHtml(initial) +
      '</div><div><div style="font-weight:600;">' +
      escapeHtml(g.user) +
      '</div><div class="mono">' +
      escapeHtml(g.realm) +
      ' · ' +
      escapeHtml(String(g.session_count)) +
      ' session(s)</div></div></div>' +
      '<div class="session-group-meta mono">' +
      '<span>' +
      escapeHtml(g.source_ip) +
      '</span><span>' +
      escapeHtml(g.duration) +
      '</span><span class="badge badge-' +
      statusClass +
      '">' +
      escapeHtml(String(g.status || '').toUpperCase()) +
      '</span></div></div></td></tr>';
    var children = (g.sessions || []).map(renderChild).join('');
    return head + children;
  }

  function emptyRow() {
    var cols = isAdmin ? 9 : 8;
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
        var groups = data.groups || [];
        var countEl = document.getElementById('sessions-count');
        if (countEl) countEl.textContent = String(sessions.length);
        var usersEl = document.getElementById('sessions-users-count');
        if (usersEl) usersEl.textContent = String(groups.length);
        updateCounts(data.counts);
        if (!groups.length) {
          tbody.innerHTML = emptyRow();
          return;
        }
        tbody.innerHTML = groups.map(renderGroup).join('');
      })
      .catch(function () {
        /* silent — keep last render */
      });
  }

  if (document.getElementById('sessions-page')) {
    setInterval(refreshSessions, POLL_MS);
  }
})();
