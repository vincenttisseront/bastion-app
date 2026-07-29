(function () {
  'use strict';

  var POLL_MS = 15000;
  var isAdmin = window.__SESSIONS_IS_ADMIN__ === true;
  var groupsCache = Array.isArray(window.__SESSIONS_BOOT__) ? window.__SESSIONS_BOOT__ : [];
  var selectedEmail = '';
  var railFilter = '';

  var TITLE_REVOKE =
    'Révoquer : supprime la session du registre bastion et invalide les cookies stockés.';
  var TITLE_ROTATE =
    'Rotation : lance le renouvellement des secrets/clés liés à cette session.';

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

  window.revokeSession = function (sessionId) {
    postAction(
      '/admin/sessions/' + encodeURIComponent(sessionId) + '/revoke',
      'Révoquer cette session ?'
    );
  };

  window.rotateKeys = function (sessionId) {
    postAction(
      '/admin/sessions/' + encodeURIComponent(sessionId) + '/rotate-keys',
      'Lancer la rotation des clés pour cette session ?'
    );
  };

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function findGroup(email) {
    for (var i = 0; i < groupsCache.length; i++) {
      if (groupsCache[i].user_email === email) return groupsCache[i];
    }
    return null;
  }

  function resolveSelected() {
    if (selectedEmail && findGroup(selectedEmail)) return selectedEmail;
    var filtered = filteredGroups();
    if (filtered.length) return filtered[0].user_email;
    if (groupsCache.length) return groupsCache[0].user_email;
    return '';
  }

  function filteredGroups() {
    var q = (railFilter || '').trim().toLowerCase();
    if (!q) return groupsCache.slice();
    return groupsCache.filter(function (g) {
      var hay = [
        g.user,
        g.user_email,
        g.realm,
        (g.auth_families || []).join(' '),
      ]
        .join(' ')
        .toLowerCase();
      return hay.indexOf(q) !== -1;
    });
  }

  function familyChips(g) {
    var families = g.auth_families || [];
    if (!families.length) return '';
    return families
      .map(function (f) {
        var label =
          f === 'oidc' ? 'OIDC' : f === 'breakglass' ? 'BG' : f === 'app' ? 'APP' : f;
        return (
          '<span class="sessions-family-chip sessions-family-' +
          escapeHtml(f) +
          '">' +
          escapeHtml(label) +
          '</span>'
        );
      })
      .join('');
  }

  function renderUserList() {
    var list = document.getElementById('sessions-user-list');
    if (!list) return;
    selectedEmail = resolveSelected();
    var visible = filteredGroups();
    if (!groupsCache.length) {
      list.innerHTML =
        '<div class="sessions-user-empty" id="sessions-user-empty">Aucun utilisateur</div>';
      return;
    }
    if (!visible.length) {
      list.innerHTML =
        '<div class="sessions-user-empty" id="sessions-user-empty">Aucun résultat pour ce filtre</div>';
      return;
    }
    list.innerHTML = visible
      .map(function (g) {
        var selected = g.user_email === selectedEmail;
        var initial = (g.user && g.user[0] ? g.user[0] : '?').toUpperCase();
        var statusClass = g.status === 'active' ? 'ok' : 'warn';
        var logoutHint = g.sso_logout
          ? '<div class="sessions-user-logout mono" title="' +
            escapeHtml(g.sso_logout.residual_note || '') +
            '">' +
            escapeHtml(g.sso_logout.label || 'Déconnexion demandée') +
            '</div>'
          : '';
        return (
          '<button type="button" class="sessions-user-item' +
          (selected ? ' is-selected' : '') +
          (g.sso_logout ? ' has-sso-logout' : '') +
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
          '</div>' +
          '<div class="sessions-user-families">' +
          familyChips(g) +
          '</div>' +
          logoutHint +
          '</div>' +
          '<span class="sessions-user-status badge badge-' +
          statusClass +
          '">' +
          escapeHtml(String(g.status || '').toUpperCase()) +
          '</span></button>'
        );
      })
      .join('');
  }

  function liveBadgeClass(s) {
    var st = s.live_status || s.status;
    if (st === 'active') return 'ok';
    if (st === 'invalid') return 'err';
    if (st === 'isolated') return 'warn';
    if (st === 'declarative' || st === 'presence') return 'info';
    return 'warn'; // unverified / unknown
  }

  function renderSessionCard(s) {
    var statusClass = liveBadgeClass(s);
    var family = s.auth_family || (s.kind === 'app' ? 'app' : 'oidc');
    var kindClass =
      family === 'breakglass' ? 'warn' : family === 'app' ? 'ok' : 'info';
    var cookieClass = s.cookies_ok ? 'ok' : 'warn';
    var liveDot =
      s.live_status === 'active' || s.live_status === 'presence'
        ? '<span class="live-dot" style="width:6px;height:6px;"></span> '
        : '';
    var statusTitle = s.verifiable
      ? 'Statut vérifié auprès de l’app cible (live)'
      : s.presence_only || s.live_status === 'presence'
        ? 'Présence SSO détectée via accès subdomain (pas une vérif cookies robotic)'
      : s.freshness && s.freshness.note
        ? s.freshness.note
        : 'Statut déclaratif côté bastion';
    var titles = s.action_titles || {};
    var footer = '';
    if (isAdmin) {
      var buttons =
        '<button type="button" class="btn btn-danger btn-sm btn-revoke" title="' +
        escapeHtml(titles.revoke || TITLE_REVOKE) +
        '" onclick="revokeSession(\'' +
        escapeHtml(s.id) +
        '\')">Révoquer cette session</button>';
      if (s.can_rotate !== false && s.kind === 'app') {
        buttons +=
          '<button type="button" class="btn btn-secondary btn-sm btn-rotate" title="' +
          escapeHtml(titles.rotate || TITLE_ROTATE) +
          '" onclick="rotateKeys(\'' +
          escapeHtml(s.id) +
          '\')">Rotation</button>';
      }
      footer =
        '<footer class="session-card-footer session-actions">' + buttons + '</footer>';
    }
    var cookieTitle = s.cookies_title || '';
    if (s.cookies_issued_at) cookieTitle += ' · émis ' + s.cookies_issued_at;
    if (s.crushauth_age) cookieTitle += ' · CrushAuth ' + s.crushauth_age;

    var verifiedMeta = '';
    if (s.verifiable) {
      verifiedMeta =
        '<div class="session-verified-meta mono">' +
        (s.last_verified_ago
          ? 'Vérifié ' + escapeHtml(s.last_verified_ago)
          : 'En attente de vérification live…') +
        '</div>';
    } else if (s.presence_only || s.live_status === 'presence') {
      verifiedMeta =
        '<div class="session-verified-meta mono" title="Heartbeat subdomain-auth">' +
        'Vu ' +
        escapeHtml(s.last_seen_ago || '—') +
        '</div>';
    } else if (s.freshness) {
      verifiedMeta =
        '<div class="session-verified-meta mono" title="' +
        escapeHtml(s.freshness.note || '') +
        '">Âge ' +
        escapeHtml(s.freshness.age_label || '—') +
        ' · ' +
        escapeHtml(s.freshness.policy_label || '') +
        '</div>';
    }

    var logoutBanner = '';
    if (s.sso_logout && s.sso_logout.label) {
      logoutBanner =
        '<div class="session-sso-logout-banner" title="' +
        escapeHtml(s.sso_logout.residual_note || '') +
        '">' +
        escapeHtml(s.sso_logout.label) +
        '</div>';
    }

    return (
      '<article class="card session-card session-card-' +
      escapeHtml(family) +
      '" data-session-id="' +
      escapeHtml(s.id) +
      '" data-kind="' +
      escapeHtml(s.kind) +
      '" data-auth-family="' +
      escapeHtml(family) +
      '">' +
      '<header class="card-header session-card-header">' +
      '<div class="session-card-title-row">' +
      '<span class="badge badge-' +
      kindClass +
      '">' +
      escapeHtml(
        s.type_label ||
          (family === 'breakglass'
            ? 'Break-glass'
            : s.kind === 'app'
              ? 'Application'
              : 'Portail OIDC')
      ) +
      '</span>' +
      '<span class="proto-tag ' +
      escapeHtml(String(s.protocol || '').toLowerCase()) +
      '">' +
      escapeHtml(s.protocol) +
      '</span></div>' +
      '<span class="badge badge-' +
      statusClass +
      '" title="' +
      escapeHtml(statusTitle) +
      '">' +
      liveDot +
      escapeHtml(s.live_status_label || String(s.status || '').toUpperCase()) +
      '</span></header>' +
      '<div class="card-body session-card-body">' +
      logoutBanner +
      '<div class="session-card-resource">' +
      escapeHtml(s.resource_title || s.target) +
      '</div>' +
      '<div class="session-card-slug mono">' +
      escapeHtml(s.resource_subtitle || '') +
      '</div>' +
      verifiedMeta +
      '<dl class="session-card-facts">' +
      '<div><dt>Type</dt><dd>' +
      escapeHtml(
        family === 'oidc'
          ? 'OIDC / Keycloak'
          : family === 'breakglass'
            ? 'Break-glass (hors Keycloak)'
            : 'Application robotic/vault'
      ) +
      '</dd></div>' +
      '<div><dt>IP client</dt><dd class="mono' +
      (s.client_ip_is_infra ? ' is-infra-ip' : '') +
      '" title="' +
      escapeHtml(s.client_ip_note || '') +
      '">' +
      escapeHtml(s.client_ip || s.source_ip || '—') +
      '</dd></div>' +
      '<div><dt>Durée</dt><dd class="mono">' +
      escapeHtml(s.duration) +
      '</dd></div>' +
      '<div><dt>Dernière activité</dt><dd title="' +
      escapeHtml(s.last_seen_label || '') +
      '">' +
      escapeHtml(s.last_seen_ago || '—') +
      '</dd></div>' +
      '<div><dt>Navigateur</dt><dd title="' +
      escapeHtml(s.browser_note || s.user_agent || '') +
      '">' +
      escapeHtml(s.user_agent_label || '—') +
      '</dd></div>' +
      '<div><dt>Cookies</dt><dd><span class="session-cookies badge badge-' +
      cookieClass +
      '" title="' +
      escapeHtml(cookieTitle) +
      '">' +
      escapeHtml(s.cookies_label || '—') +
      '</span></dd></div>' +
      (String(s.protocol || '').toUpperCase() === 'BREAKGLASS' && s.jti
        ? '<div><dt>jti</dt><dd class="mono" title="Identifiant JWT break-glass">' +
          escapeHtml(String(s.jti).slice(0, 8)) +
          '…</dd></div>'
        : '') +
      '</dl></div>' +
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
    if (!groupsCache.length) {
      detail.innerHTML =
        '<div class="sessions-detail-empty" id="sessions-detail-empty">' +
        '<div class="empty-state">' +
        '<div class="empty-title">Aucune session active</div>' +
        '<div class="empty-desc">Les connexions portail et les ouvertures d’applications apparaîtront ici.</div>' +
        '</div></div>';
      return;
    }
    if (!g || (railFilter && filteredGroups().every(function (x) { return x.user_email !== g.user_email; }))) {
      detail.innerHTML =
        '<div class="sessions-detail-empty" id="sessions-detail-empty">' +
        '<div class="empty-state">' +
        '<div class="empty-title">Sélectionnez un utilisateur</div>' +
        '<div class="empty-desc">Choisissez un utilisateur dans le bandeau pour voir le détail de ses sessions.</div>' +
        '</div></div>';
      return;
    }
    var statusClass = g.status === 'active' ? 'ok' : 'warn';
    var disconnectBtn = '';
    if (isAdmin && g.show_disconnect !== false && (g.has_oidc || g.has_app)) {
      disconnectBtn =
        '<button type="button" class="btn btn-danger btn-sm" ' +
        'title="Révoque sessions robotic/vault + logout Keycloak. Hors break-glass. Délai résiduel cookie ~1h possible." ' +
        'onclick="disconnectUser(' +
        JSON.stringify(g.user_email) +
        ', ' +
        JSON.stringify(g.realm) +
        ')">Déconnecter cet utilisateur</button>';
    } else if (isAdmin && g.has_breakglass && !g.has_oidc && !g.has_app) {
      disconnectBtn =
        '<span class="form-hint" title="Break-glass n’a pas de session Keycloak">Utiliser « Révoquer » sur la session break-glass</span>';
    }
    var logoutBanner = '';
    if (g.sso_logout && g.sso_logout.label) {
      logoutBanner =
        '<div class="session-sso-logout-banner" style="margin-bottom:var(--sp-3);" title="' +
        escapeHtml(g.sso_logout.residual_note || '') +
        '">' +
        escapeHtml(g.sso_logout.label) +
        '</div>';
    }
    detail.innerHTML =
      '<div class="sessions-detail-head">' +
      '<div><h2 class="sessions-detail-title">' +
      escapeHtml(g.user) +
      '</h2><p class="sessions-detail-sub mono">' +
      escapeHtml(g.user_email) +
      ' · ' +
      escapeHtml(g.realm) +
      '</p>' +
      '<div class="sessions-user-families" style="margin-top:6px;">' +
      familyChips(g) +
      '</div></div>' +
      '<div style="display:flex;gap:var(--sp-2);align-items:center;flex-wrap:wrap;">' +
      '<span class="badge badge-' +
      statusClass +
      '">' +
      escapeHtml(String(g.session_count)) +
      ' session(s)</span>' +
      disconnectBtn +
      '</div></div>' +
      logoutBanner +
      '<div id="disconnect-user-result" style="margin:0 0 var(--sp-3);"></div>' +
      '<div class="sessions-card-grid" id="sessions-card-grid">' +
      (g.sessions || []).map(renderSessionCard).join('') +
      '</div>';
  }

  window.disconnectUser = async function (userEmail, realmSlug) {
    var ok = window.bastionConfirm
      ? await window.bastionConfirm({
          title: 'Déconnecter cet utilisateur ?',
          message:
            'Révoque les sessions robotic/vault puis logout Keycloak Admin. ' +
            'Le break-glass n’est pas concerné. Le cookie portail peut rester ' +
            'valide jusqu’à ~1 h (cookie_refresh).',
          confirmLabel: 'Déconnecter',
          danger: true,
        })
      : window.confirm('Déconnecter cet utilisateur ?');
    if (!ok) return;
    var resultEl = document.getElementById('disconnect-user-result');
    if (resultEl) resultEl.innerHTML = '<div class="form-hint">Déconnexion en cours…</div>';
    try {
      var url =
        '/admin/users/' +
        encodeURIComponent(userEmail) +
        '/sessions/disconnect?realm_slug=' +
        encodeURIComponent(realmSlug || '');
      var resp = await fetch(url, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        credentials: 'same-origin',
      });
      var data = await resp.json().catch(function () {
        return {};
      });
      var app = data.app_sessions || {};
      var sso = data.sso || {};
      var appLine =
        app.ok === false
          ? 'Sessions app : échec — ' + (app.error || 'erreur')
          : 'Sessions app : ' +
            (app.revoked_count || 0) +
            ' révoquée(s)' +
            (app.failed_count ? ', ' + app.failed_count + ' échec(s)' : '');
      if (app.failed && app.failed.length) {
        appLine +=
          ' (' +
          app.failed
            .map(function (f) {
              return (f.target || f.session_id) + ': ' + (f.error || '');
            })
            .join('; ') +
          ')';
      }
      var ssoLine = sso.ok
        ? 'SSO Keycloak : logout OK'
        : 'SSO Keycloak : échec — ' + (sso.error || data.error || 'erreur');
      var residual = sso.residual_note
        ? '<p class="form-hint" style="margin-top:8px;">' +
          escapeHtml(sso.residual_note) +
          '</p>'
        : '';
      if (resultEl) {
        resultEl.innerHTML =
          '<div class="alert ' +
          (app.ok !== false && sso.ok ? 'alert-ok' : 'alert-warn') +
          '" style="margin:0;"><div>' +
          escapeHtml(appLine) +
          '</div><div style="margin-top:8px;">' +
          escapeHtml(ssoLine) +
          '</div>' +
          residual +
          '</div>';
      }
      // Refresh list so SSO logout badge appears without full reload delay
      setTimeout(function () {
        refreshSessions();
      }, 400);
    } catch (e) {
      if (resultEl) {
        resultEl.innerHTML =
          '<div class="alert alert-err" style="margin:0;">Erreur réseau.</div>';
      }
    }
  };

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
    liveVerifySelected();
  }

  function liveVerifySelected() {
    selectedEmail = resolveSelected();
    if (!selectedEmail) return Promise.resolve();
    return fetch('/api/sessions/live-verify', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCsrfToken(),
        'Content-Type': 'application/json',
      },
      credentials: 'same-origin',
      body: JSON.stringify({ user_email: selectedEmail }),
    })
      .then(function (r) {
        if (!r.ok) throw new Error('live-verify failed');
        return r.json();
      })
      .then(function (data) {
        if (data.groups) {
          groupsCache = data.groups;
        }
        if (data.sessions) {
          var countEl = document.getElementById('sessions-count');
          if (countEl) countEl.textContent = String(data.sessions.length);
        }
        if (data.counts) updateCounts(data.counts);
        var usersEl = document.getElementById('sessions-users-count');
        if (usersEl && data.groups) usersEl.textContent = String(data.groups.length);
        renderAll();
      })
      .catch(function () {
        /* keep last render */
      });
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
        return liveVerifySelected();
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
    var filterInput = document.getElementById('sessions-user-filter');
    if (filterInput) {
      filterInput.addEventListener('input', function () {
        railFilter = filterInput.value || '';
        renderAll();
      });
    }
    liveVerifySelected();
    setInterval(refreshSessions, POLL_MS);
  }
})();
