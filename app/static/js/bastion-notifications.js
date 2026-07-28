(function () {
  'use strict';

  function qs(sel, root) {
    return (root || document).querySelector(sel);
  }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function severityClass(sev) {
    if (sev === 'error' || sev === 'err') return 'err';
    if (sev === 'warn' || sev === 'warning') return 'warn';
    if (sev === 'success' || sev === 'ok') return 'ok';
    return 'info';
  }

  function init() {
    var root = qs('#notif-center');
    if (!root) return;

    var btn = qs('#notifications-btn', root);
    var panel = qs('#notif-panel', root);
    var feed = qs('[data-notif-feed]', root);
    var countEl = qs('[data-notif-count]', root);
    var dot = qs('[data-notif-dot]', root);
    if (!btn || !panel || !feed) return;

    var open = false;
    var loaded = false;

    function setOpen(next) {
      open = !!next;
      panel.hidden = !open;
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        panel.focus();
        loadFeed();
      }
    }

    function updateBadge(count) {
      var n = parseInt(count, 10) || 0;
      if (countEl) {
        if (n > 0) {
          countEl.hidden = false;
          countEl.textContent = n > 99 ? '99+' : String(n);
        } else {
          countEl.hidden = true;
          countEl.textContent = '';
        }
      }
      if (dot) {
        // Numeric badge replaces the plain red dot
        if (n > 0 && countEl && !countEl.hidden) dot.setAttribute('hidden', '');
        else if (n > 0) dot.removeAttribute('hidden');
        else dot.setAttribute('hidden', '');
      }
      btn.setAttribute(
        'aria-label',
        n > 0 ? 'Notifications (' + n + ')' : 'Notifications'
      );
    }

    function renderShortcuts(shortcuts) {
      var wrap = qs('[data-notif-shortcuts]', root);
      if (!wrap) return;
      if (!shortcuts || !shortcuts.length) {
        wrap.innerHTML = '';
        return;
      }
      wrap.innerHTML = shortcuts
        .map(function (s) {
          return (
            '<a class="notif-shortcut" href="' +
            esc(s.href) +
            '" title="' +
            esc(s.hint || '') +
            '">' +
            '<span class="notif-shortcut-label">' +
            esc(s.label) +
            '</span>' +
            (s.hint
              ? '<span class="notif-shortcut-hint">' + esc(s.hint) + '</span>'
              : '') +
            '</a>'
          );
        })
        .join('');
    }

    function renderItems(items) {
      if (!items || !items.length) {
        feed.innerHTML =
          '<div class="notif-empty">' +
          '<p class="notif-empty-title">Rien d’urgent</p>' +
          '<p class="notif-empty-desc">Pas de domaines en attente ni d’accès refusés récents. Utilisez les raccourcis ci-dessous.</p>' +
          '</div>';
        return;
      }
      feed.innerHTML = items
        .map(function (it) {
          var sev = severityClass(it.severity);
          return (
            '<a class="notif-item" href="' +
            esc(it.href || '#') +
            '">' +
            '<span class="dot dot-' +
            sev +
            '" aria-hidden="true"></span>' +
            '<span class="notif-item-body">' +
            '<span class="notif-item-title">' +
            esc(it.title) +
            '</span>' +
            (it.body
              ? '<span class="notif-item-text">' + esc(it.body) + '</span>'
              : '') +
            (it.time
              ? '<span class="notif-item-time">' + esc(it.time) + '</span>'
              : '') +
            '</span>' +
            '</a>'
          );
        })
        .join('');
    }

    function loadFeed() {
      feed.innerHTML =
        '<div class="notif-loading"><span class="notif-spinner" aria-hidden="true"></span> Chargement…</div>';
      fetch('/api/admin/notifications', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (data) {
          loaded = true;
          updateBadge(data.count || 0);
          renderItems(data.items || []);
          renderShortcuts(data.shortcuts || []);
        })
        .catch(function () {
          feed.innerHTML =
            '<div class="notif-empty"><p class="notif-empty-title">Impossible de charger</p>' +
            '<p class="notif-empty-desc">Réessayez ou ouvrez Logs / Domaines depuis le menu.</p></div>';
        });
    }

    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      setOpen(!open);
    });

    document.addEventListener('click', function (e) {
      if (!open) return;
      if (root.contains(e.target)) return;
      setOpen(false);
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && open) {
        setOpen(false);
        btn.focus();
      }
    });

    // Prefetch badge count without opening the panel
    fetch('/api/admin/notifications', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (data) {
        if (data) updateBadge(data.count || 0);
        else updateBadge(0);
      })
      .catch(function () {
        updateBadge(0);
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
