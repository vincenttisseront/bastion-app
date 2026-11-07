(function () {
  'use strict';

  // Live feed: server-sent events (/api/sessions/stream) push verified
  // snapshots on change; polling is only the fallback when the stream is down.
  var FALLBACK_POLL_MS = 10000;
  var STALE_AFTER_MS = 35000;
  var STREAM_RETRY_MS = 15000;
  var isAdmin = window.__SESSIONS_IS_ADMIN__ === true;
  var groupsCache = Array.isArray(window.__SESSIONS_BOOT__) ? window.__SESSIONS_BOOT__ : [];
  var clockOffsetMs = 0;
  var lastMessageAt = 0;
  var stream = null;
  var streamRetryTimer = null;
  var fallbackTimer = null;
  var expectingReconnect = false;
  var previousStates = {};
  var selectedEmail = '';
  var railFilter = '';
  var openSessionId = null;
  var previousFocus = null;

  var TITLE_REVOKE =
    BastionI18n.t(
      'Révoquer : supprime la session du registre bastion et invalide les cookies stockés.'
    );
  var TITLE_ROTATE =
    BastionI18n.t(
      'Rotation : lance le renouvellement des secrets/clés liés à cette session.'
    );

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
        title: BastionI18n.t("Confirmer l'action"),
        message: confirmMsg,
        confirmLabel: BastionI18n.t('Confirmer'),
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
          title: BastionI18n.t('Erreur'),
          message: BastionI18n.t("Erreur lors de l'exécution de l'action."),
        });
      });
  }

  window.revokeSession = function (sessionId) {
    void postAction(
      '/admin/sessions/' + encodeURIComponent(sessionId) + '/revoke',
      BastionI18n.t('Révoquer cette session ?')
    );
  };

  window.rotateKeys = function (sessionId) {
    void postAction(
      '/admin/sessions/' + encodeURIComponent(sessionId) + '/rotate-keys',
      BastionI18n.t('Lancer la rotation des clés pour cette session ?')
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
    if (!root || root.dataset.sessionActionsBound === '1') return;
    root.dataset.sessionActionsBound = '1';
    root.addEventListener('click', function (event) {
      var btn = event.target.closest('[data-session-action]');
      if (!btn || !root.contains(btn)) return;
      var action = btn.dataset.sessionAction;
      var sessionId = btn.dataset.sessionId || '';
      if (action === 'revoke' && sessionId) {
        event.preventDefault();
        window.revokeSession(sessionId);
      } else if (action === 'rotate' && sessionId) {
        event.preventDefault();
        window.rotateKeys(sessionId);
      } else if (action === 'disconnect-user') {
        event.preventDefault();
        var email = btn.dataset.userEmail || '';
        var realm = btn.dataset.realm || '';
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

  /* ── Live clock & formatting (ticked every second, server-aligned) ──── */

  function syncClock(iso) {
    var t = Date.parse(iso || '');
    if (!isNaN(t)) clockOffsetMs = t - Date.now();
  }

  function serverNow() {
    return Date.now() + clockOffsetMs;
  }

  function secondsSince(iso) {
    var t = Date.parse(iso || '');
    if (isNaN(t)) return null;
    return Math.max(0, Math.floor((serverNow() - t) / 1000));
  }

  function secondsUntil(iso) {
    var t = Date.parse(iso || '');
    if (isNaN(t)) return null;
    return Math.floor((t - serverNow()) / 1000);
  }

  function tf(msgid, vars) {
    var out = BastionI18n.t(msgid);
    Object.keys(vars || {}).forEach(function (k) {
      out = out.split('{' + k + '}').join(String(vars[k]));
    });
    return out;
  }

  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function fmtDuration(sec) {
    if (sec == null || sec < 0) sec = 0;
    var h = Math.floor(sec / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    if (h) return h + 'h ' + pad2(m) + 'm';
    if (m) return m + 'm ' + pad2(s) + 's';
    return s + 's';
  }

  function fmtAgo(iso) {
    var s = secondsSince(iso);
    if (s == null) return '—';
    if (s < 60) return tf('il y a {s}s', { s: s });
    if (s < 3600) return tf('il y a {m} min', { m: Math.floor(s / 60) });
    if (s < 86400) return tf('il y a {h} h', { h: Math.floor(s / 3600) });
    return tf('il y a {d} j', { d: Math.floor(s / 86400) });
  }

  function fmtLeft(iso) {
    var s = secondsUntil(iso);
    if (s == null) return '—';
    if (s <= 0) return BastionI18n.t('échu');
    return tf('dans {d}', { d: fmtDuration(s) });
  }

  function fmtAbsolute(iso) {
    var t = Date.parse(iso || '');
    if (isNaN(t)) return '';
    try {
      return new Date(t).toLocaleString();
    } catch (e) {
      return String(iso);
    }
  }

  function liveAgo(iso) {
    if (!iso) return '—';
    return (
      '<span data-live-ago="' +
      escapeHtml(iso) +
      '" title="' +
      escapeHtml(fmtAbsolute(iso)) +
      '">' +
      escapeHtml(fmtAgo(iso)) +
      '</span>'
    );
  }

  function liveDuration(iso) {
    if (!iso) return '—';
    return (
      '<span data-live-dur="' +
      escapeHtml(iso) +
      '">' +
      escapeHtml(fmtDuration(secondsSince(iso))) +
      '</span>'
    );
  }

  function liveLeft(iso, approx) {
    if (!iso) return '—';
    return (
      (approx ? '≈ ' : '') +
      '<span data-live-left="' +
      escapeHtml(iso) +
      '" title="' +
      escapeHtml(fmtAbsolute(iso)) +
      '">' +
      escapeHtml(fmtLeft(iso)) +
      '</span>'
    );
  }

  function tickLive() {
    document.querySelectorAll('[data-live-ago]').forEach(function (el) {
      el.textContent = fmtAgo(el.getAttribute('data-live-ago'));
    });
    document.querySelectorAll('[data-live-dur]').forEach(function (el) {
      el.textContent = fmtDuration(secondsSince(el.getAttribute('data-live-dur')));
    });
    document.querySelectorAll('[data-live-left]').forEach(function (el) {
      el.textContent = fmtLeft(el.getAttribute('data-live-left'));
    });
    refreshPillTitle();
  }

  /* ── Verified status presentation ──────────────────────────────────── */

  var STATE_CLASS = {
    online: 'ok',
    idle: 'muted',
    unverified: 'warn',
    invalid: 'err',
    isolated: 'warn',
  };

  function stateClass(st) {
    return STATE_CLASS[st] || 'muted';
  }

  function activityOf(s) {
    return s.activity_at || s.last_seen_at || null;
  }

  function statusTitleOf(s) {
    var v = s.verification || {};
    return [s.live_status_title, v.summary].filter(Boolean).join(' — ');
  }

  function stateBadgeHtml(s, extraClass) {
    var st = s.live_status || 'unverified';
    return (
      '<span class="' +
      (extraClass ? extraClass + ' ' : '') +
      'badge badge-' +
      stateClass(st) +
      ' session-state session-state--' +
      escapeHtml(st) +
      '" title="' +
      escapeHtml(statusTitleOf(s)) +
      '">' +
      (st === 'online' ? '<span class="live-dot live-dot-sm"></span> ' : '') +
      escapeHtml(s.live_status_label || st.toUpperCase()) +
      '</span>'
    );
  }

  function factHtml(label, valueHtml, opts) {
    opts = opts || {};
    return (
      '<div><dt>' +
      escapeHtml(label) +
      '</dt><dd' +
      (opts.mono ? ' class="mono"' : '') +
      (opts.title ? ' title="' + escapeHtml(opts.title) + '"' : '') +
      '>' +
      valueHtml +
      '</dd></div>'
    );
  }

  function verificationHtml(s) {
    var v = s.verification || {};
    var approx = v.method === 'oauth2_proxy';
    var rows =
      factHtml(BastionI18n.t('Source'), escapeHtml(v.method_label || '—')) +
      factHtml(BastionI18n.t('Résultat'), escapeHtml(v.summary || '—'));
    if (v.continuous) {
      rows += factHtml(
        BastionI18n.t('Vérifié'),
        escapeHtml(BastionI18n.t('en continu (à chaque mise à jour du flux)'))
      );
    } else if (v.checked_at) {
      rows += factHtml(BastionI18n.t('Vérifié'), liveAgo(v.checked_at));
    }
    if (v.expires_at) {
      rows += factHtml(BastionI18n.t('Expiration'), liveLeft(v.expires_at, approx));
    }
    if (v.idle_expires_at) {
      rows += factHtml(
        BastionI18n.t('Coupure inactivité'),
        liveLeft(v.idle_expires_at, false),
        {
          title: BastionI18n.t(
            'Sans nouvelle requête portail, le jeton est refusé à cette échéance.'
          ),
        }
      );
    }
    if (v.credentials > 1) {
      rows += factHtml(BastionI18n.t('Jetons valides'), escapeHtml(String(v.credentials)));
    }
    return (
      '<section class="session-verify session-verify--' +
      escapeHtml(s.live_status || 'unverified') +
      '" aria-label="' +
      escapeHtml(BastionI18n.t('Vérification')) +
      '"><h3 class="session-verify-title">' +
      escapeHtml(BastionI18n.t('Vérification')) +
      '</h3><dl class="session-card-facts">' +
      rows +
      '</dl></section>'
    );
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
        ? BastionI18n.t('Break-glass')
        : s.kind === 'app'
          ? BastionI18n.t('Application')
          : BastionI18n.t('Portail OIDC'))
    );
  }

  function typeDetailOf(family) {
    if (family === 'oidc') return BastionI18n.t('OIDC / Keycloak');
    if (family === 'breakglass') return BastionI18n.t('Break-glass (hors Keycloak)');
    return BastionI18n.t('Application robotic/vault');
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
      var match = row.dataset.sessionId === sessionId && open;
      row.classList.toggle('is-open', match);
      row.setAttribute('aria-expanded', match ? 'true' : 'false');
    });
  }

  function fillSessionDetailPanel(s) {
    var els = drawerEls();
    if (!els.drawer || !s) return;
    var family = familyOf(s);
    var kindClass =
      family === 'breakglass' ? 'warn' : family === 'app' ? 'ok' : 'info';
    var cookieClass = s.cookies_ok ? 'ok' : 'warn';
    var cookieTitle = s.cookies_title || '';
    if (s.cookies_issued_at)
      cookieTitle += ' · ' + BastionI18n.t('émis') + ' ' + s.cookies_issued_at;
    if (s.crushauth_age) cookieTitle += ' · CrushAuth ' + s.crushauth_age;

    if (els.title) {
      els.title.textContent =
        s.resource_title || s.target || BastionI18n.t('Session');
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
        '<div class="session-binding-banner" title="' +
        BastionI18n.t('Ancrage inhabituel') +
        '">⚠ ' +
        BastionI18n.t('IP/empreinte inhabituelle') +
        '</div>';
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
        stateBadgeHtml(s) +
        '</div>' +
        verificationHtml(s) +
        '<dl class="session-card-facts">' +
        '<div><dt>' +
        BastionI18n.t('Type') +
        '</dt><dd>' +
        escapeHtml(typeDetailOf(family)) +
        '</dd></div>' +
        '<div><dt>' +
        BastionI18n.t('IP client') +
        '</dt><dd class="mono' +
        (s.client_ip_is_infra ? ' is-infra-ip' : '') +
        '" title="' +
        escapeHtml(s.client_ip_note || '') +
        '">' +
        escapeHtml(s.client_ip || s.source_ip || '—') +
        '</dd></div>' +
        '<div><dt>' +
        BastionI18n.t('Durée') +
        '</dt><dd class="mono">' +
        liveDuration(s.started_at) +
        '</dd></div>' +
        '<div><dt>' +
        BastionI18n.t('Dernière activité') +
        '</dt><dd>' +
        liveAgo(activityOf(s)) +
        '</dd></div>' +
        '<div><dt>' +
        BastionI18n.t('Navigateur') +
        '</dt><dd title="' +
        escapeHtml(s.browser_note || s.user_agent || '') +
        '">' +
        escapeHtml(s.user_agent_label || '—') +
        '</dd></div>' +
        (family === 'app'
          ? '<div><dt>' +
            BastionI18n.t('User applicatif') +
            '</dt><dd class="mono" title="' +
            escapeHtml(
              s.credential_source
                ? BastionI18n.t('Source vault :') +
                  ' ' +
                  String(s.credential_source)
                : BastionI18n.t(
                    'Compte utilisé pour ouvrir la session robotic/vault'
                  )
            ) +
            '">' +
            escapeHtml(s.robotic_username || '—') +
            '</dd></div>'
          : '') +
        '<div><dt>' +
        BastionI18n.t('Cookies') +
        '</dt><dd><span class="session-cookies badge badge-' +
        cookieClass +
        '" title="' +
        escapeHtml(cookieTitle) +
        '">' +
        escapeHtml(s.cookies_label || '—') +
        '</span></dd></div>' +
        (String(s.protocol || '').toUpperCase() === 'BREAKGLASS' && s.jti
          ? '<div><dt>jti</dt><dd class="mono" title="' +
            BastionI18n.t('Identifiant JWT break-glass') +
            '">' +
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
        revokeBtn.dataset.sessionAction = 'revoke';
        revokeBtn.dataset.sessionId = String(s.id || '');
        revokeBtn.textContent = BastionI18n.t('Révoquer cette session');
        els.actions.appendChild(revokeBtn);
        if (s.can_rotate !== false && s.kind === 'app') {
          var rotateBtn = document.createElement('button');
          rotateBtn.type = 'button';
          rotateBtn.className = 'btn btn-secondary btn-sm btn-rotate';
          rotateBtn.title = titles.rotate || TITLE_ROTATE;
          rotateBtn.dataset.sessionAction = 'rotate';
          rotateBtn.dataset.sessionId = String(s.id || '');
          rotateBtn.textContent = BastionI18n.t('Rotation');
          els.actions.appendChild(rotateBtn);
        }
        var logsLink = document.createElement('a');
        logsLink.className = 'btn btn-ghost btn-sm';
        logsLink.href = logsUrlForSession(s);
        logsLink.target = '_blank';
        logsLink.rel = 'noopener noreferrer';
        if (s.kind === 'app' && (s.target || '').trim()) {
          logsLink.title =
            BastionI18n.t('Access log nginx de l’application') +
            ' ' +
            String(s.target).trim();
          logsLink.textContent = BastionI18n.t('Access log app');
        } else {
          logsLink.title = BastionI18n.t(
            'Ouvre Logs (audit) filtré sur cet utilisateur'
          );
          logsLink.textContent = BastionI18n.t('Voir les logs');
        }
        els.actions.appendChild(logsLink);
        if (s.kind === 'app') {
          var auditLink = document.createElement('a');
          auditLink.className = 'btn btn-ghost btn-sm';
          auditLink.href = auditUrlForSession(s);
          auditLink.target = '_blank';
          auditLink.rel = 'noopener noreferrer';
          auditLink.title = BastionI18n.t(
            'Audit filtré sur l’acteur (pas l’id de session — non écrit en AuditLog)'
          );
          auditLink.textContent = BastionI18n.t('Audit acteur');
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
    var kindClass =
      family === 'breakglass' ? 'warn' : family === 'app' ? 'ok' : 'info';
    var isOpen = openSessionId === s.id;
    var changed =
      previousStates[s.id] !== undefined && previousStates[s.id] !== s.live_status;
    return (
      '<li><button type="button" class="session-row session-row-' +
      escapeHtml(family) +
      ' session-row--' +
      escapeHtml(s.live_status || 'unverified') +
      (isOpen ? ' is-open' : '') +
      (changed ? ' is-updated' : '') +
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
      stateBadgeHtml(s, 'session-row-status') +
      '<span class="session-row-meta mono" title="' +
      escapeHtml(BastionI18n.t('Durée')) +
      '">' +
      liveDuration(s.started_at) +
      '</span>' +
      '<span class="session-row-meta session-row-ago" title="' +
      escapeHtml(BastionI18n.t('Dernière activité authentifiée')) +
      '">' +
      liveAgo(activityOf(s)) +
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
        '<div class="sessions-user-empty" id="sessions-user-empty">' +
        BastionI18n.t('Aucun utilisateur') +
        '</div>';
      return;
    }
    if (!visible.length) {
      list.innerHTML =
        '<div class="sessions-user-empty" id="sessions-user-empty">' +
        BastionI18n.t('Aucun résultat pour ce filtre') +
        '</div>';
      return;
    }
    list.innerHTML = visible
      .map(function (g) {
        var selected = g.user_email === selectedEmail;
        var initial = (g.user && g.user[0] ? g.user[0] : '?').toUpperCase();
        var subParts = [];
        if (g.realm) subParts.push(escapeHtml(g.realm));
        subParts.push(
          escapeHtml(String(g.session_count)) + ' ' + escapeHtml(BastionI18n.t('session(s)'))
        );
        var logoutHint = g.sso_logout
          ? '<div class="sessions-user-logout mono" title="' +
            escapeHtml(g.sso_logout.residual_note || '') +
            '">' +
            escapeHtml(g.sso_logout.label || BastionI18n.t('Déconnexion demandée')) +
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
          subParts.join(' · ') +
          '</div>' +
          '<div class="sessions-user-families">' +
          familyChips(g) +
          '</div>' +
          logoutHint +
          '</div>' +
          '<span class="sessions-user-state">' +
          stateBadgeHtml(
            {
              live_status: g.live_status,
              live_status_label: g.live_status_label,
              live_status_title:
                g.online_count > 0
                  ? tf('{n} session(s) en ligne', { n: g.online_count })
                  : '',
            },
            'sessions-user-status'
          ) +
          (g.activity_at
            ? '<span class="sessions-user-seen mono">' + liveAgo(g.activity_at) + '</span>'
            : '') +
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
    if (page) page.dataset.selectedEmail = selectedEmail || '';

    var g = findGroup(selectedEmail);
    if (!groupsCache.length) {
      closeSessionDetailPanel();
      detail.innerHTML =
        '<div class="sessions-detail-empty" id="sessions-detail-empty">' +
        '<div class="empty-state">' +
        '<div class="empty-title">' +
        BastionI18n.t('Aucune session active') +
        '</div>' +
        '<div class="empty-desc">' +
        BastionI18n.t(
          'Les connexions portail et les ouvertures d’applications apparaîtront ici.'
        ) +
        '</div>' +
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
        '<div class="empty-title">' +
        BastionI18n.t('Sélectionnez un utilisateur') +
        '</div>' +
        '<div class="empty-desc">' +
        BastionI18n.t(
          'Choisissez un utilisateur dans le bandeau pour voir le détail de ses sessions.'
        ) +
        '</div>' +
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

    var disconnectBtn = '';
    if (isAdmin && g.show_disconnect !== false && (g.has_oidc || g.has_app)) {
      disconnectBtn =
        '<button type="button" class="btn btn-danger btn-sm" ' +
        'title="' +
        BastionI18n.t(
          'Révoque sessions robotic/vault + session native portail + logout Keycloak. Hors break-glass. Cookie oauth2-proxy résiduel ~1h possible.'
        ) +
        '" ' +
        'data-session-action="disconnect-user" data-user-email="' +
        escapeHtml(g.user_email) +
        '" data-realm="' +
        escapeHtml(g.realm) +
        '">' +
        BastionI18n.t('Déconnecter cet utilisateur') +
        '</button>';
    } else if (isAdmin && g.has_breakglass && !g.has_oidc && !g.has_app) {
      disconnectBtn =
        '<span class="form-hint" title="' +
        BastionI18n.t('Break-glass n’a pas de session Keycloak') +
        '">' +
        BastionI18n.t('Utiliser « Révoquer » sur la session break-glass') +
        '</span>';
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
    sub.textContent =
      (g.user_email || '') +
      (g.realm ? ' · ' + g.realm : g.has_breakglass ? ' · ' + BastionI18n.t('hors realm (break-glass)') : '');
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
    countBadge.className = 'badge badge-' + stateClass(g.live_status);
    countBadge.textContent =
      String(g.session_count) +
      ' ' +
      BastionI18n.t('session(s)') +
      (g.online_count ? ' · ' + tf('{n} en ligne', { n: g.online_count }) : '');
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
          title: BastionI18n.t('Déconnecter cet utilisateur ?'),
          message: BastionI18n.t(
            'Révoque les sessions robotic/vault, la session native portail '
            + '(bastion_session) et demande le logout Keycloak. Le break-glass '
            + 'n’est pas concerné. Un éventuel cookie oauth2-proxy peut rester '
            + 'valide jusqu’à ~1 h (cookie_refresh).'
          ),
          confirmLabel: BastionI18n.t('Déconnecter'),
          danger: true,
        })
      : false;
    if (!ok) return;
    var resultEl = document.getElementById('disconnect-user-result');
    if (resultEl)
      resultEl.innerHTML =
        '<div class="form-hint">' +
        BastionI18n.t('Déconnexion en cours…') +
        '</div>';
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
      var appLine;
      if (app.ok === false) {
        appLine =
          BastionI18n.t('Sessions app : échec —') +
          ' ' +
          (app.error || BastionI18n.t('erreur'));
      } else {
        appLine =
          BastionI18n.t('Sessions app :') +
          ' ' +
          (app.revoked_count || 0) +
          ' ' +
          BastionI18n.t('révoquée(s)');
        if (app.failed_count) {
          appLine +=
            ', ' + app.failed_count + ' ' + BastionI18n.t('échec(s)');
        }
      }
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
        ? BastionI18n.t('SSO Keycloak : logout OK')
        : BastionI18n.t('SSO Keycloak : échec —') +
          ' ' +
          (sso.error || data.error || BastionI18n.t('erreur'));
      var localBits = [];
      if (sso.native_oidc_revoked != null) {
        localBits.push(
          BastionI18n.t('JWT natif :') +
            ' ' +
            (sso.native_oidc_revoked || 0) +
            ' ' +
            BastionI18n.t('révoqué(s)')
        );
      }
      if (sso.portal_rows_removed != null) {
        localBits.push(
          BastionI18n.t('registre portail :') +
            ' ' +
            (sso.portal_rows_removed || 0) +
            ' ' +
            BastionI18n.t('retiré(s)')
        );
      }
      var localLine = localBits.length
        ? '<div style="margin-top:8px;">' + escapeHtml(localBits.join(' · ')) + '</div>'
        : '';
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
          localLine +
          residual +
          '</div>';
      }
      setTimeout(function () {
        void refreshSessions();
      }, 400);
    } catch (e) {
      if (resultEl) {
        resultEl.innerHTML =
          '<div class="alert alert-err" style="margin:0;">' +
          BastionI18n.t('Erreur réseau.') +
          '</div>';
      }
    }
  };

  function focusKeyOf(el) {
    if (!el || !el.dataset) return null;
    if (el.closest && el.closest('#session-detail-drawer')) {
      return el.dataset.sessionAction ? 'a:' + el.dataset.sessionAction : null;
    }
    if (el.dataset.sessionId && el.classList.contains('session-row')) {
      return 's:' + el.dataset.sessionId;
    }
    if (el.dataset.userEmail && el.classList.contains('sessions-user-item')) {
      return 'u:' + el.dataset.userEmail;
    }
    return null;
  }

  function restoreFocus(key) {
    if (!key) return;
    var kind = key.slice(0, 2);
    var value = key.slice(2);
    var nodes;
    if (kind === 's:') nodes = document.querySelectorAll('.session-row');
    else if (kind === 'u:') nodes = document.querySelectorAll('.sessions-user-item');
    else nodes = document.querySelectorAll('#session-detail-actions [data-session-action]');
    for (var i = 0; i < nodes.length; i++) {
      var d = nodes[i].dataset;
      var match =
        kind === 's:'
          ? d.sessionId === value
          : kind === 'u:'
            ? d.userEmail === value
            : d.sessionAction === value;
      if (match) {
        try {
          nodes[i].focus({ preventScroll: true });
        } catch (e) {
          nodes[i].focus();
        }
        return;
      }
    }
  }

  function rememberStates() {
    var next = {};
    groupsCache.forEach(function (g) {
      (g.sessions || []).forEach(function (s) {
        next[s.id] = s.live_status;
      });
    });
    previousStates = next;
  }

  function renderAll() {
    var focusKey = focusKeyOf(document.activeElement);
    renderUserList();
    renderDetail();
    restoreFocus(focusKey);
    rememberStates();
  }

  function updateCounts(counts) {
    if (!counts) return;
    document.querySelectorAll('.session-kind-tab').forEach(function (tab) {
      var k = tab.dataset.kind;
      var el = tab.querySelector('.session-kind-count');
      if (!el) return;
      if (k === 'all') el.textContent = counts.all != null ? counts.all : '0';
      else if (k === 'user') el.textContent = counts.user != null ? counts.user : '0';
      else if (k === 'app') el.textContent = counts.app != null ? counts.app : '0';
    });
  }

  function applySnapshot(data) {
    if (!data) return;
    if (data.server_time) syncClock(data.server_time);
    groupsCache = Array.isArray(data.groups) ? data.groups : [];
    var total =
      data.total != null ? data.total : Array.isArray(data.sessions) ? data.sessions.length : null;
    var countEl = document.getElementById('sessions-count');
    if (countEl && total != null) countEl.textContent = String(total);
    var usersEl = document.getElementById('sessions-users-count');
    if (usersEl) usersEl.textContent = String(groupsCache.length);
    updateCounts(data.counts);
    renderAll();
  }

  /* ── LIVE pill: reflects the feed, never decorative ──────────────────── */

  var PILL_LABELS = {
    connecting: 'Connexion…',
    live: 'Live',
    stale: 'Reconnexion…',
    polling: 'Différé',
  };

  function setPill(mode) {
    var pill = document.getElementById('sessions-live-pill');
    if (!pill) return;
    pill.dataset.mode = mode;
    pill.classList.toggle('is-stale', mode !== 'live');
    var label = document.getElementById('sessions-live-label');
    if (label) label.textContent = BastionI18n.t(PILL_LABELS[mode] || 'Live');
    refreshPillTitle();
  }

  function refreshPillTitle() {
    var pill = document.getElementById('sessions-live-pill');
    if (!pill) return;
    var mode = pill.dataset.mode || 'connecting';
    var since = lastMessageAt
      ? tf('dernière mise à jour il y a {s}s', {
          s: Math.max(0, Math.floor((Date.now() - lastMessageAt) / 1000)),
        })
      : BastionI18n.t('en attente du flux');
    var head =
      mode === 'live'
        ? BastionI18n.t('Flux temps réel actif : statuts re-vérifiés côté serveur toutes les 2 s')
        : mode === 'polling'
          ? BastionI18n.t('Flux temps réel indisponible : rafraîchissement périodique')
          : BastionI18n.t('Flux temps réel interrompu : reconnexion en cours');
    pill.title = head + ' — ' + since;
  }

  function markMessage() {
    lastMessageAt = Date.now();
    stopFallback();
    setPill('live');
  }

  function checkStale() {
    if (document.hidden) return;
    if (lastMessageAt && Date.now() - lastMessageAt > STALE_AFTER_MS) {
      var pill = document.getElementById('sessions-live-pill');
      if (pill && pill.dataset.mode === 'live') setPill('stale');
      startFallback();
    }
  }

  /* ── Fallback polling (stream unavailable) ─────────────────────────── */

  function pageKind() {
    var page = document.getElementById('sessions-page');
    var kind = (page && page.dataset.kind) || 'all';
    return kind === 'user' || kind === 'app' ? kind : '';
  }

  function liveVerifySelected() {
    selectedEmail = resolveSelected();
    if (!selectedEmail) return Promise.resolve();
    var body = { user_email: selectedEmail };
    var kind = pageKind();
    if (kind) body.kind = kind;
    return fetch('/api/sessions/live-verify', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCsrfToken(),
        'Content-Type': 'application/json',
      },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    })
      .then(function (r) {
        if (!r.ok) throw new Error('live-verify failed');
        return r.json();
      })
      .then(applySnapshot)
      .catch(function () {
        /* keep last render */
      });
  }

  function refreshSessions() {
    var kind = pageKind();
    var url = '/api/sessions' + (kind ? '?kind=' + encodeURIComponent(kind) : '');
    return fetch(url, { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('poll failed');
        return r.json();
      })
      .then(function (data) {
        applySnapshot(data);
        // Polling has no server-side probe loop: probe the selected user here.
        if (fallbackTimer) return liveVerifySelected();
        return null;
      })
      .catch(function () {
        /* silent — keep last render */
      });
  }

  function startFallback() {
    if (fallbackTimer) return;
    setPill('polling');
    fallbackTimer = setInterval(function () {
      if (!document.hidden) void refreshSessions();
    }, FALLBACK_POLL_MS);
    void refreshSessions();
  }

  function stopFallback() {
    if (!fallbackTimer) return;
    clearInterval(fallbackTimer);
    fallbackTimer = null;
  }

  /* ── Server-sent events ───────────────────────────────────────────── */

  function streamUrl() {
    var kind = pageKind();
    return '/api/sessions/stream' + (kind ? '?kind=' + encodeURIComponent(kind) : '');
  }

  function closeStream() {
    if (streamRetryTimer) {
      clearTimeout(streamRetryTimer);
      streamRetryTimer = null;
    }
    if (stream) {
      stream.close();
      stream = null;
    }
  }

  function scheduleStreamRetry() {
    if (streamRetryTimer || document.hidden) return;
    streamRetryTimer = setTimeout(function () {
      streamRetryTimer = null;
      openStream();
    }, STREAM_RETRY_MS);
  }

  function parseEvent(ev) {
    try {
      return JSON.parse(ev.data || '{}');
    } catch (e) {
      return {};
    }
  }

  function openStream() {
    if (stream || document.hidden) return;
    if (typeof window.EventSource !== 'function') {
      startFallback();
      return;
    }
    if (!lastMessageAt) setPill('connecting');
    var es = new window.EventSource(streamUrl());
    stream = es;
    es.addEventListener('snapshot', function (ev) {
      expectingReconnect = false;
      applySnapshot(parseEvent(ev));
      markMessage();
    });
    es.addEventListener('ping', function (ev) {
      expectingReconnect = false;
      var data = parseEvent(ev);
      if (data.server_time) syncClock(data.server_time);
      markMessage();
    });
    es.addEventListener('degraded', function () {
      setPill('stale');
    });
    es.addEventListener('timeout', function () {
      // Planned server-side rotation: EventSource reconnects by itself.
      expectingReconnect = true;
    });
    es.onerror = function () {
      if (es.readyState === window.EventSource.CLOSED) {
        // Auth failure or non-stream answer: no auto-retry — poll, retry later.
        if (stream === es) stream = null;
        startFallback();
        scheduleStreamRetry();
        return;
      }
      if (!expectingReconnect) setPill('stale');
    };
  }

  function onVisibilityChange() {
    if (document.hidden) {
      closeStream();
      stopFallback();
      return;
    }
    openStream();
  }

  function onUserClick(ev) {
    var btn = ev.target.closest('.sessions-user-item');
    if (!btn) return;
    selectedEmail = btn.dataset.userEmail || '';
    closeSessionDetailPanel();
    renderAll();
    if (fallbackTimer) void liveVerifySelected();
  }

  function onSessionRowClick(ev) {
    var row = ev.target.closest('.session-row');
    if (!row) return;
    var id = row.dataset.sessionId;
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

  var page = document.getElementById('sessions-page');
  if (page) {
    selectedEmail = page.dataset.selectedEmail || '';
    syncClock(window.__SESSIONS_SERVER_TIME__);
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
    document.addEventListener('visibilitychange', onVisibilityChange);
    window.addEventListener('pagehide', closeStream);
    // Client render from the boot payload: same markup as live updates.
    if (document.getElementById('sessions-split')) renderAll();
    setInterval(tickLive, 1000);
    setInterval(checkStale, 5000);
    openStream();
  }
})();
