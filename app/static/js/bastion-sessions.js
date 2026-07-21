(function () {
  'use strict';

  var POLL_MS = 15000;
  var isAdmin = window.__SESSIONS_IS_ADMIN__ === true;
  var groupsCache = Array.isArray(window.__SESSIONS_BOOT__) ? window.__SESSIONS_BOOT__ : [];
  var selectedEmail = '';

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

  function findGroup(email) {
    for (var i = 0; i < groupsCache.length; i++) {
      if (groupsCache[i].user_email === email) return groupsCache[i];
    }
    return null;
  }

  function resolveSelected() {
    if (selectedEmail && findGroup(selectedEmail)) return selectedEmail;
    if (groupsCache.length) return groupsCache[0].user_email;
    return '';
  }

  function renderUserList() {
    var list = document.getElementById('sessions-user-list');
    if (!list) return;
    selectedEmail = resolveSelected();
    if (!groupsCache.length) {
      list.innerHTML = '<div class="sessions-user-empty" id="sessions-user-empty">Aucun utilisateur</div>';
      return;
    }
    list.innerHTML = groupsCache
      .map(function (g) {
        var selected = g.user_email === selectedEmail;
        var initial = (g.user && g.user[0] ? g.user[0] : '?').toUpperCase();
        var statusClass = g.status === 'active' ? 'ok' : 'warn';
        return (
          '<button type="button" class="sessions-user-item' +
          (selected ? ' is-selected' : '') +
          '" role="option" aria-selected="' +
          (selected ? 'true' : 'false') +
          '" data-user-email="' +
          escapeHtml(g.user_email) +
          '" data-realm="' +
          escapeHtml(g.realm) +
          '">' +
          '<div class="user-avatar sessions-user-avatar">' +
          escapeHtml(initial) +
          '</div>' +
          '<div class="sessions-user-meta">' +
          '<div class="sessions-user-name">' +
          escapeHtml(g.user) +
          '</div>' +
          '<div class="sessions-user-sub mono">' +
          escapeHtml(g.realm) +
          ' · ' +
          escapeHtml(String(g.session_count)) +
          '</div></div>' +
          '<span class="sessions-user-status badge badge-' +
          statusClass +
          '">' +
          escapeHtml(String(g.status || '').toUpperCase()) +
          '</span></button>'
        );
      })
      .join('');
  }

  function renderSessionCard(s) {
    var statusClass = s.status === 'active' ? 'ok' : 'warn';
    var kindClass = s.kind === 'user' ? 'info' : 'ok';
    var cookieClass = s.cookies_ok ? 'ok' : 'warn';
    var liveDot =
      s.status === 'active'
        ? '<span class="live-dot" style="width:6px;height:6px;"></span> '
        : '';
    var footer = '';
    if (isAdmin) {
      footer =
        '<footer class="session-card-footer session-actions">' +
        '<button type="button" class="btn-isolate" onclick="isolateSession(\'' +
        escapeHtml(s.id) +
        '\')">Isoler</button>' +
        '<button type="button" class="btn-rotate" onclick="rotateKeys(\'' +
        escapeHtml(s.id) +
        '\')">Rotation</button></footer>';
    }
    return (
      '<article class="session-card" data-session-id="' +
      escapeHtml(s.id) +
      '" data-kind="' +
      escapeHtml(s.kind) +
      '">' +
      '<header class="session-card-header">' +
      '<div class="session-card-title-row">' +
      '<span class="badge badge-' +
      kindClass +
      '">' +
      kindLabel(s.kind) +
      '</span>' +
      '<span class="proto-tag ' +
      escapeHtml(String(s.protocol || '').toLowerCase()) +
      '">' +
      escapeHtml(s.protocol) +
      '</span></div>' +
      '<span class="badge badge-' +
      statusClass +
      '">' +
      liveDot +
      escapeHtml(String(s.status || '').toUpperCase()) +
      '</span></header>' +
      '<div class="session-card-body">' +
      '<div class="session-card-resource mono">' +
      escapeHtml(s.target) +
      '</div>' +
      '<dl class="session-card-facts">' +
      '<div><dt>IP source</dt><dd class="mono">' +
      escapeHtml(s.source_ip) +
      '</dd></div>' +
      '<div><dt>Durée</dt><dd class="mono">' +
      escapeHtml(s.duration) +
      '</dd></div>' +
      '<div><dt>Cookies</dt><dd><span class="session-cookies badge badge-' +
      cookieClass +
      '" title="' +
      escapeHtml(cookieTitle(s)) +
      '">' +
      escapeHtml(s.cookies_label || '—') +
      '</span></dd></div></dl></div>' +
      footer +
      '</article>'
    );
  }

  function renderDetail() {
    var detail = document.getElementById('sessions-detail');
    if (!detail) return;
    selectedEmail = resolveSelected();
    var page = document.getElementById('sessions-page');
    if (page) page.setAttribute('data-selected-email', selectedEmail || '');

    var g = findGroup(selectedEmail);
    if (!g) {
      detail.innerHTML =
        '<div class="sessions-detail-empty" id="sessions-detail-empty">' +
        '<div class="empty-state">' +
        '<div class="empty-title">Aucune session active</div>' +
        '<div class="empty-desc">Les connexions portail et les ouvertures d’applications apparaîtront ici.</div>' +
        '</div></div>';
      return;
    }
    var statusClass = g.status === 'active' ? 'ok' : 'warn';
    detail.innerHTML =
      '<div class="sessions-detail-head">' +
      '<div><h2 class="sessions-detail-title">' +
      escapeHtml(g.user) +
      '</h2><p class="sessions-detail-sub mono">' +
      escapeHtml(g.user_email) +
      ' · ' +
      escapeHtml(g.realm) +
      ' · IP ' +
      escapeHtml(g.source_ip) +
      '</p></div>' +
      '<span class="badge badge-' +
      statusClass +
      '">' +
      escapeHtml(String(g.session_count)) +
      ' session(s)</span></div>' +
      '<div class="sessions-card-grid" id="sessions-card-grid">' +
      (g.sessions || []).map(renderSessionCard).join('') +
      '</div>';
  }

  function renderAll() {
    renderUserList();
    renderDetail();
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

  function onUserClick(ev) {
    var btn = ev.target.closest('.sessions-user-item');
    if (!btn) return;
    selectedEmail = btn.getAttribute('data-user-email') || '';
    renderAll();
  }

  function refreshSessions() {
    var page = document.getElementById('sessions-page');
    if (!page) return;
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
        groupsCache = data.groups || [];
        var countEl = document.getElementById('sessions-count');
        if (countEl) countEl.textContent = String(sessions.length);
        var usersEl = document.getElementById('sessions-users-count');
        if (usersEl) usersEl.textContent = String(groupsCache.length);
        updateCounts(data.counts);
        renderAll();
      })
      .catch(function () {
        /* silent — keep last render */
      });
  }

  var page = document.getElementById('sessions-page');
  if (page) {
    selectedEmail = page.getAttribute('data-selected-email') || '';
    var list = document.getElementById('sessions-user-list');
    if (list) list.addEventListener('click', onUserClick);
    setInterval(refreshSessions, POLL_MS);
  }
})();
