(function () {
  'use strict';

  var POLL_MS = 15000;
  var isAdmin = window.__SESSIONS_IS_ADMIN__ === true;
  var groupsCache = Array.isArray(window.__SESSIONS_BOOT__) ? window.__SESSIONS_BOOT__ : [];
  var selectedEmail = '';
  var railFilter = '';
  var openSessionId = null;
  var previousFocus = null;

  var TITLE_REVOKE =
    'Révoquer : supprime la session du registre bastion et invalide les cookies stockés.';
  var TITLE_ROTATE =
    'Rotation : lance le renouvellement des secrets/clés liés à cette session.';

  var ICON_APP =
    '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>';
  var ICON_PORTAL =
    '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>';
  var ICON_BG =
    '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  async function postAction(url, confirmMsg) {
    if (confirmMsg) {
      var ok = await window.bastionConfirm({
        title: "Confirmer l'action",
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
          message: "Erreur lors de l'exécution de l'action.",
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
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/`/g, '&#96;');
  }

  function bindSessionActionClicks(root) {
    if (!root || root.getAttribute('data-session-actions-bound') === '1') return;
    root.setAttribute('data-session-actions-bound', '1');
    root.addEventListener('click', function (event) {
      var btn = event.target.closest('[data-session-action]');
      if (!btn || !root.contains(btn)) return;
      var action = btn.getAttribute('data-session-action');
      var sessionId = btn.getAttribute('data-session-id') || '';
      if (action === 'revoke' && sessionId) {
        event.preventDefault();
        window.revokeSession(sessionId);
      } else if (action === 'rotate' && sessionId) {
        event.preventDefault();
        window.rotateKeys(sessionId);
      } else if (action === 'disconnect-user') {
        event.preventDefault();
        var email = btn.getAttribute('data-user-email') || '';
        var realm = btn.getAttribute('data-realm') || '';
        if (email) window.disconnectUser(email, realm);
      }
    });
  }

  function findGroup(email) {
    for (var i = 0; i < groupsCache.length; i++) {
      if (groupsCache[i].user_email === email) return groupsCache[i];
    }
    return null;
  }

  function findSession(sessionId) {
    for (var i = 0; i < groupsCache.length; i++) {
      var sessions = groupsCache[i].sessions || [];
      for (var j = 0; j < sessions.length; j++) {
        if (sessions[j].id === sessionId) return sessions[j];
      }
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

  function liveBadgeClass(s) {
    var st = s.live_status || s.status;
    if (st === 'active') return 'ok';
    if (st === 'invalid') return 'err';
    if (st === 'isolated') return 'warn';
    if (st === 'declarative' || st === 'presence') return 'info';
    return 'warn';
  }

  function familyOf(s) {
    return s.auth_family || (s.kind === 'app' ? 'app' : 'oidc');
  }

  function familyIcon(family) {
    if (family === 'app') return ICON_APP;
    if (family === 'breakglass') return ICON_BG;
    return ICON_PORTAL;
  }

  function typeLabelOf(s, family) {
    return (
      s.type_label ||
      (family === 'breakglass'
        ? 'Break-glass'
        : s.kind === 'app'
          ? 'Application'
          : 'Portail OIDC')
    );
  }

  function typeDetailOf(family) {
    if (family === 'oidc') return 'OIDC / Keycloak';
    if (family === 'breakglass') return 'Break-glass (hors Keycloak)';
    return 'Application robotic/vault';
  }

  function statusTitleOf(s) {
    if (s.verifiable) return 'Statut vérifié auprès de l’app cible (live)';
    if (s.presence_only || s.live_status === 'presence') {
      return 'Présence SSO détectée via accès subdomain (pas une vérif cookies robotic)';
    }
    if (s.freshness && s.freshness.note) return s.freshness.note;
    return 'Statut déclaratif côté bastion';
  }

  function verifiedMetaHtml(s) {
    if (s.verifiable) {
      return (
        '<div class="session-verified-meta mono">' +
        (s.last_verified_ago
          ? 'Vérifié ' + escapeHtml(s.last_verified_ago)
          : 'En attente de vérification live…') +
        '</div>'
      );
    }
    if (s.presence_only || s.live_status === 'presence') {
      return (
        '<div class="session-verified-meta mono" title="Heartbeat subdomain-auth">' +
        'Vu ' +
        escapeHtml(s.last_seen_ago || '—') +
        '</div>'
      );
    }
    if (s.freshness) {
      return (
        '<div class="session-verified-meta mono" title="' +
        escapeHtml(s.freshness.note || '') +
        '">Âge ' +
        escapeHtml(s.freshness.age_label || '—') +
        ' · ' +
        escapeHtml(s.freshness.policy_label || '') +
        '</div>'
      );
    }
    return '';
  }

  /* ── SessionDetailPanel (drawer) ─────────────────────────────────────── */

  function drawerEls() {
    return {
      backdrop: document.getElementById('session-detail-backdrop'),
      drawer: document.getElementById('session-detail-drawer'),
      title: document.getElementById('session-detail-title'),
      subtitle: document.getElementById('session-detail-subtitle'),
      body: document.getElementById('session-detail-body'),
      actions: document.getElementById('session-detail-actions'),
      closeBtn: document.getElementById('session-detail-close'),
    };
  }

  function drawerFocusables() {
    var els = drawerEls();
    if (!els.drawer || els.drawer.hidden) return [];
    return Array.prototype.slice
      .call(
        els.drawer.querySelectorAll(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
      )
      .filter(function (el) {
        return el.offsetParent !== null || el === document.activeElement;
      });
  }

  function markRowExpanded(sessionId, open) {
    document.querySelectorAll('.session-row').forEach(function (row) {
      var match = row.getAttribute('data-session-id') === sessionId && open;
      row.classList.toggle('is-open', match);
      row.setAttribute('aria-expanded', match ? 'true' : 'false');
    });
  }

  function fillSessionDetailPanel(s) {
    var els = drawerEls();
    if (!els.drawer || !s) return;
    var family = familyOf(s);
    var statusClass = liveBadgeClass(s);
    var kindClass =
      family === 'breakglass' ? 'warn' : family === 'app' ? 'ok' : 'info';
    var cookieClass = s.cookies_ok ? 'ok' : 'warn';
    var liveDot =
      s.live_status === 'active' || s.live_status === 'presence'
        ? '<span class="live-dot live-dot-sm"></span> '
        : '';
    var cookieTitle = s.cookies_title || '';
    if (s.cookies_issued_at) cookieTitle += ' · émis ' + s.cookies_issued_at;
    if (s.crushauth_age) cookieTitle += ' · CrushAuth ' + s.crushauth_age;

    if (els.title) {
      els.title.textContent = s.resource_title || s.target || 'Session';
    }
    if (els.subtitle) {
      els.subtitle.textContent = s.resource_subtitle || '';
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
    var bindingBanner = '';
    if (s.identity_binding && s.identity_binding.unusual) {
      bindingBanner =
        '<div class="session-binding-banner" title="Ancrage inhabituel">⚠ IP/empreinte inhabituelle</div>';
    }

    if (els.body) {
      els.body.innerHTML =
        logoutBanner +
        bindingBanner +
        '<div class="session-detail-chips">' +
        '<span class="badge badge-' +
        kindClass +
        '">' +
        escapeHtml(typeLabelOf(s, family)) +
        '</span>' +
        '<span class="proto-tag ' +
        escapeHtml(String(s.protocol || '').toLowerCase()) +
        '">' +
        escapeHtml(s.protocol || '') +
        '</span>' +
        '<span class="badge badge-' +
        statusClass +
        '" title="' +
        escapeHtml(statusTitleOf(s)) +
        '">' +
        liveDot +
        escapeHtml(s.live_status_label || String(s.status || '').toUpperCase()) +
        '</span></div>' +
        verifiedMetaHtml(s) +
        '<dl class="session-card-facts">' +
        '<div><dt>Type</dt><dd>' +
        escapeHtml(typeDetailOf(family)) +
        '</dd></div>' +
        '<div><dt>IP client</dt><dd class="mono' +
        (s.client_ip_is_infra ? ' is-infra-ip' : '') +
        '" title="' +
        escapeHtml(s.client_ip_note || '') +
        '">' +
        escapeHtml(s.client_ip || s.source_ip || '—') +
        '</dd></div>' +
        '<div><dt>Durée</dt><dd class="mono">' +
        escapeHtml(s.duration || '—') +
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
        (family === 'app'
          ? '<div><dt>User applicatif</dt><dd class="mono" title="' +
            escapeHtml(
              s.credential_source
                ? 'Source vault : ' + String(s.credential_source)
                : 'Compte utilisé pour ouvrir la session robotic/vault'
            ) +
            '">' +
            escapeHtml(s.robotic_username || '—') +
            '</dd></div>'
          : '') +
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
        '</dl>';
    }

    if (els.actions) {
      if (!isAdmin) {
        els.actions.innerHTML = '';
        els.actions.hidden = true;
      } else {
        var titles = s.action_titles || {};
        els.actions.textContent = '';
        var revokeBtn = document.createElement('button');
        revokeBtn.type = 'button';
        revokeBtn.className = 'btn btn-danger btn-sm btn-revoke';
        revokeBtn.title = titles.revoke || TITLE_REVOKE;
        revokeBtn.setAttribute('data-session-action', 'revoke');
        revokeBtn.setAttribute('data-session-id', String(s.id || ''));
        revokeBtn.textContent = 'Révoquer cette session';
        els.actions.appendChild(revokeBtn);
        if (s.can_rotate !== false && s.kind === 'app') {
          var rotateBtn = document.createElement('button');
          rotateBtn.type = 'button';
          rotateBtn.className = 'btn btn-secondary btn-sm btn-rotate';
          rotateBtn.title = titles.rotate || TITLE_ROTATE;
          rotateBtn.setAttribute('data-session-action', 'rotate');
          rotateBtn.setAttribute('data-session-id', String(s.id || ''));
          rotateBtn.textContent = 'Rotation';
          els.actions.appendChild(rotateBtn);
        }
        var logsLink = document.createElement('a');
        logsLink.className = 'btn btn-ghost btn-sm';
        logsLink.href = logsUrlForSession(s);
        logsLink.target = '_blank';
        logsLink.rel = 'noopener noreferrer';
        if (s.kind === 'app' && (s.target || '').trim()) {
          logsLink.title =
            'Access log nginx de l’application ' + String(s.target).trim();
          logsLink.textContent = 'Access log app';
        } else {
          logsLink.title = 'Ouvre Logs (audit) filtré sur cet utilisateur';
          logsLink.textContent = 'Voir les logs';
        }
        els.actions.appendChild(logsLink);
        if (s.kind === 'app') {
          var auditLink = document.createElement('a');
          auditLink.className = 'btn btn-ghost btn-sm';
          auditLink.href = auditUrlForSession(s);
          auditLink.target = '_blank';
          auditLink.rel = 'noopener noreferrer';
          auditLink.title =
            'Audit filtré sur l’acteur (pas l’id de session — non écrit en AuditLog)';
          auditLink.textContent = 'Audit acteur';
          els.actions.appendChild(auditLink);
        }
        bindSessionActionClicks(els.actions);
        els.actions.hidden = false;
      }
    }
  }

  function logsUrlForSession(s) {
    // App browsing traffic is in nginx access logs. ActiveSession ids
    // (app:email:slug) are never written into AuditLog.details — deep-linking
    // audit with detail= + multi-word q + IP looked like "empty retention".
    if (s.kind === 'app' && (s.target || '').trim()) {
      return (
        '/admin/logs?app=' +
        encodeURIComponent(String(s.target).trim()) +
        '#app-access'
      );
    }
    return auditUrlForSession(s);
  }

  function auditUrlForSession(s) {
    var params = new URLSearchParams();
    var actor = (s.user_email || s.username || '').trim();
    if (actor) params.set('actor', actor);
    if (s.kind === 'app' && (s.target || '').trim()) {
      params.set('q', String(s.target).trim());
    }
    return '/admin/logs?' + params.toString() + '#audit';
  }

  function openSessionDetailPanel(sessionId) {
    var s = findSession(sessionId);
    var els = drawerEls();
    if (!s || !els.drawer) return;
    previousFocus = document.activeElement;
    openSessionId = sessionId;
    fillSessionDetailPanel(s);
    els.drawer.hidden = false;
    if (els.backdrop) {
      els.backdrop.hidden = false;
      els.backdrop.classList.add('is-open');
    }
    els.drawer.classList.add('is-open');
    document.body.classList.add('session-detail-open');
    markRowExpanded(sessionId, true);
    window.setTimeout(function () {
      if (els.closeBtn) els.closeBtn.focus();
    }, 0);
  }

  function closeSessionDetailPanel() {
    var els = drawerEls();
    openSessionId = null;
    markRowExpanded('', false);
    if (els.drawer) {
      els.drawer.classList.remove('is-open');
      els.drawer.hidden = true;
    }
    if (els.backdrop) {
      els.backdrop.classList.remove('is-open');
      els.backdrop.hidden = true;
    }
    document.body.classList.remove('session-detail-open');
    if (previousFocus && typeof previousFocus.focus === 'function') {
      try {
        previousFocus.focus();
      } catch (e) {
        /* ignore */
      }
    }
    previousFocus = null;
  }

  function toggleSessionDetailPanel(sessionId) {
    if (openSessionId === sessionId) {
      closeSessionDetailPanel();
      return;
    }
    openSessionDetailPanel(sessionId);
  }

  window.SessionDetailPanel = {
    open: openSessionDetailPanel,
    close: closeSessionDetailPanel,
    toggle: toggleSessionDetailPanel,
  };

  /* ── Compact row ─────────────────────────────────────────────────────── */

  function renderSessionRow(s) {
    var family = familyOf(s);
    var statusClass = liveBadgeClass(s);
    var kindClass =
      family === 'breakglass' ? 'warn' : family === 'app' ? 'ok' : 'info';
    var liveDot =
      s.live_status === 'active'
        ? '<span class="live-dot live-dot-sm"></span> '
        : '';
    var isOpen = openSessionId === s.id;
    return (
      '<li><button type="button" class="session-row session-row-' +
      escapeHtml(family) +
      (isOpen ? ' is-open' : '') +
      '" data-session-id="' +
      escapeHtml(s.id) +
      '" data-kind="' +
      escapeHtml(s.kind) +
      '" data-auth-family="' +
      escapeHtml(family) +
      '" aria-expanded="' +
      (isOpen ? 'true' : 'false') +
      '" aria-controls="session-detail-drawer">' +
      '<span class="session-row-icon session-row-icon--' +
      escapeHtml(family) +
      '" aria-hidden="true">' +
      familyIcon(family) +
      '</span>' +
      '<span class="session-row-main">' +
      '<span class="session-row-title truncate">' +
      escapeHtml(s.resource_title || s.target || '') +
      '</span>' +
      '<span class="session-row-slug mono truncate">' +
      escapeHtml(s.resource_subtitle || '') +
      '</span></span>' +
      '<span class="session-row-badges">' +
      '<span class="badge badge-' +
      kindClass +
      '">' +
      escapeHtml(typeLabelOf(s, family)) +
      '</span>' +
      '<span class="proto-tag ' +
      escapeHtml(String(s.protocol || '').toLowerCase()) +
      '">' +
      escapeHtml(s.protocol || '') +
      '</span></span>' +
      '<span class="session-row-status badge badge-' +
      statusClass +
      '" title="' +
      escapeHtml(statusTitleOf(s)) +
      '">' +
      liveDot +
      escapeHtml(s.live_status_label || String(s.status || '').toUpperCase()) +
      '</span>' +
      '<span class="session-row-meta mono" title="Durée">' +
      escapeHtml(s.duration || '—') +
      '</span>' +
      '<span class="session-row-meta session-row-ago" title="' +
      escapeHtml(s.last_seen_label || '') +
      '">' +
      escapeHtml(s.last_seen_ago || '—') +
      '</span>' +
      '<span class="session-row-chevron" aria-hidden="true">' +
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>' +
      '</span></button></li>'
    );
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

  function renderDetail() {
    var detail = document.getElementById('sessions-detail');
    if (!detail) return;
    selectedEmail = resolveSelected();
    var page = document.getElementById('sessions-page');
    if (page) page.setAttribute('data-selected-email', selectedEmail || '');

    var g = findGroup(selectedEmail);
    if (!groupsCache.length) {
      closeSessionDetailPanel();
      detail.innerHTML =
        '<div class="sessions-detail-empty" id="sessions-detail-empty">' +
        '<div class="empty-state">' +
        '<div class="empty-title">Aucune session active</div>' +
        '<div class="empty-desc">Les connexions portail et les ouvertures d’applications apparaîtront ici.</div>' +
        '</div></div>';
      return;
    }
    if (
      !g ||
      (railFilter &&
        filteredGroups().every(function (x) {
          return x.user_email !== g.user_email;
        }))
    ) {
      closeSessionDetailPanel();
      detail.innerHTML =
        '<div class="sessions-detail-empty" id="sessions-detail-empty">' +
        '<div class="empty-state">' +
        '<div class="empty-title">Sélectionnez un utilisateur</div>' +
        '<div class="empty-desc">Choisissez un utilisateur dans le bandeau pour voir le détail de ses sessions.</div>' +
        '</div></div>';
      return;
    }

    // Keep drawer open only if the session still belongs to this user.
    if (openSessionId) {
      var stillThere = (g.sessions || []).some(function (s) {
        return s.id === openSessionId;
      });
      if (!stillThere) closeSessionDetailPanel();
      else {
        var current = findSession(openSessionId);
        if (current) fillSessionDetailPanel(current);
      }
    }

    var statusClass = g.status === 'active' ? 'ok' : 'warn';
    var disconnectBtn = '';
    if (isAdmin && g.show_disconnect !== false && (g.has_oidc || g.has_app)) {
      disconnectBtn =
        '<button type="button" class="btn btn-danger btn-sm" ' +
        'title="Révoque sessions robotic/vault + logout Keycloak. Hors break-glass. Délai résiduel cookie ~1h possible." ' +
        'data-session-action="disconnect-user" data-user-email="' +
        escapeHtml(g.user_email) +
        '" data-realm="' +
        escapeHtml(g.realm) +
        '">Déconnecter cet utilisateur</button>';
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
    // Build via DOM so user-controlled strings never go through innerHTML assignment.
    var head = document.createElement('div');
    head.className = 'sessions-detail-head';
    var headLeft = document.createElement('div');
    var title = document.createElement('h2');
    title.className = 'sessions-detail-title';
    title.textContent = g.user || '';
    var sub = document.createElement('p');
    sub.className = 'sessions-detail-sub mono';
    sub.textContent = (g.user_email || '') + ' · ' + (g.realm || '');
    var families = document.createElement('div');
    families.className = 'sessions-user-families';
    families.style.marginTop = '6px';
    families.insertAdjacentHTML('afterbegin', familyChips(g));
    headLeft.appendChild(title);
    headLeft.appendChild(sub);
    headLeft.appendChild(families);
    var actions = document.createElement('div');
    actions.className = 'session-actions-group';
    var countBadge = document.createElement('span');
    countBadge.className = 'badge badge-' + statusClass;
    countBadge.textContent = String(g.session_count) + ' session(s)';
    actions.appendChild(countBadge);
    if (disconnectBtn) {
      var disconnectWrap = document.createElement('div');
      disconnectWrap.insertAdjacentHTML('afterbegin', disconnectBtn);
      while (disconnectWrap.firstChild) {
        actions.appendChild(disconnectWrap.firstChild);
      }
    }
    head.appendChild(headLeft);
    head.appendChild(actions);

    detail.textContent = '';
    detail.appendChild(head);
    if (logoutBanner) {
      var bannerWrap = document.createElement('div');
      bannerWrap.insertAdjacentHTML('afterbegin', logoutBanner);
      while (bannerWrap.firstChild) {
        detail.appendChild(bannerWrap.firstChild);
      }
    }
    var resultSlot = document.createElement('div');
    resultSlot.id = 'disconnect-user-result';
    resultSlot.className = 'session-detail-spacer';
    detail.appendChild(resultSlot);
    var list = document.createElement('ul');
    list.className = 'sessions-row-list';
    list.id = 'sessions-card-grid';
    list.setAttribute('role', 'list');
    list.insertAdjacentHTML(
      'afterbegin',
      (g.sessions || []).map(renderSessionRow).join('')
    );
    detail.appendChild(list);
    bindSessionActionClicks(detail);
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
      : false;
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
    closeSessionDetailPanel();
    renderAll();
    liveVerifySelected();
  }

  function onSessionRowClick(ev) {
    var row = ev.target.closest('.session-row');
    if (!row) return;
    var id = row.getAttribute('data-session-id');
    if (!id) return;
    toggleSessionDetailPanel(id);
  }

  function onDrawerKeydown(e) {
    if (!openSessionId) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      closeSessionDetailPanel();
      return;
    }
    if (e.key !== 'Tab') return;
    var nodes = drawerFocusables();
    if (!nodes.length) return;
    var first = nodes[0];
    var last = nodes[nodes.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
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
    var detail = document.getElementById('sessions-detail');
    if (detail) detail.addEventListener('click', onSessionRowClick);
    var filterInput = document.getElementById('sessions-user-filter');
    if (filterInput) {
      filterInput.addEventListener('input', function () {
        railFilter = filterInput.value || '';
        renderAll();
      });
    }
    var els = drawerEls();
    if (els.closeBtn) {
      els.closeBtn.addEventListener('click', function (e) {
        e.preventDefault();
        closeSessionDetailPanel();
      });
    }
    if (els.backdrop) {
      els.backdrop.addEventListener('click', function () {
        closeSessionDetailPanel();
      });
    }
    document.addEventListener('keydown', onDrawerKeydown);
    liveVerifySelected();
    setInterval(refreshSessions, POLL_MS);
  }
})();
