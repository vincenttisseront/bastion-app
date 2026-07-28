(function () {
  'use strict';

  var FETCH_MS = 8000;

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
    var dismissAllBtn = qs('[data-notif-dismiss-all]', root);
    if (!btn || !panel || !feed) return;

    var open = false;
    var cache = null;
    var inflight = null;
    var ignoreDocClickUntil = 0;

    function setOpen(next) {
      open = !!next;
      panel.hidden = !open;
      if (open) {
        panel.classList.add('is-open');
        root.classList.add('is-open');
        panel.removeAttribute('hidden');
      } else {
        panel.classList.remove('is-open');
        root.classList.remove('is-open');
        panel.setAttribute('hidden', '');
      }
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        ignoreDocClickUntil = Date.now() + 300;
        try {
          panel.focus({ preventScroll: true });
        } catch (e) {
          panel.focus();
        }
        loadFeed(false);
      }
    }

    function updateBadge(count) {
      var n = parseInt(count, 10) || 0;
      if (countEl) {
        if (n > 0) {
          countEl.hidden = false;
          countEl.removeAttribute('hidden');
          countEl.textContent = n > 99 ? '99+' : String(n);
        } else {
          countEl.hidden = true;
          countEl.setAttribute('hidden', '');
          countEl.textContent = '';
        }
      }
      if (dot) {
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
      if (dismissAllBtn) {
        if (items && items.length) {
          dismissAllBtn.hidden = false;
          dismissAllBtn.removeAttribute('hidden');
        } else {
          dismissAllBtn.hidden = true;
          dismissAllBtn.setAttribute('hidden', '');
        }
      }
      if (!items || !items.length) {
        feed.innerHTML =
          '<div class="notif-empty">' +
          '<p class="notif-empty-title">Rien d’urgent</p>' +
          '<p class="notif-empty-desc">Pas de notification active. Les éléments marqués comme lus réapparaissent si le problème change.</p>' +
          '</div>';
        return;
      }
      feed.innerHTML = items
        .map(function (it) {
          var sev = severityClass(it.severity);
          var dismiss =
            it.dismissible === false
              ? ''
              : '<button type="button" class="notif-dismiss" data-notif-dismiss="' +
                esc(it.id) +
                '" data-notif-fp="' +
                esc(it.fingerprint || '') +
                '" title="Marquer comme lu" aria-label="Marquer comme lu">×</button>';
          return (
            '<div class="notif-item-wrap">' +
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
            '</a>' +
            dismiss +
            '</div>'
          );
        })
        .join('');
    }

    function applyData(data) {
      cache = data;
      updateBadge(data.count || 0);
      renderItems(data.items || []);
      renderShortcuts(data.shortcuts || []);
    }

    function showError(msg) {
      feed.innerHTML =
        '<div class="notif-empty"><p class="notif-empty-title">Impossible de charger</p>' +
        '<p class="notif-empty-desc">' +
        esc(msg || 'Réessayez ou ouvrez Logs / Domaines depuis le menu.') +
        '</p></div>';
    }

    function fetchFeed() {
      if (inflight) return inflight;
      var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      var timer = null;
      if (ctrl) {
        timer = setTimeout(function () {
          try {
            ctrl.abort();
          } catch (e) {}
        }, FETCH_MS);
      }
      inflight = fetch('/api/admin/notifications', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        signal: ctrl ? ctrl.signal : undefined,
      })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .finally(function () {
          if (timer) clearTimeout(timer);
          inflight = null;
        });
      return inflight;
    }

    function loadFeed(silent) {
      if (cache && !silent) {
        applyData(cache);
      } else if (!silent) {
        feed.innerHTML =
          '<div class="notif-loading"><span class="notif-spinner" aria-hidden="true"></span> Chargement…</div>';
      }
      fetchFeed()
        .then(function (data) {
          applyData(data);
        })
        .catch(function (err) {
          if (cache) {
            applyData(cache);
            return;
          }
          var aborted = err && err.name === 'AbortError';
          showError(
            aborted
              ? 'Délai dépassé — les journaux sont peut‑être saturés. Ouvrez Logs.'
              : null
          );
        });
    }

    function postDismiss(url, body) {
      return fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : '{}',
      }).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      });
    }

    feed.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.getAttribute) return;
      var id = t.getAttribute('data-notif-dismiss');
      if (!id) return;
      e.preventDefault();
      e.stopPropagation();
      var fp = t.getAttribute('data-notif-fp') || '';
      postDismiss('/api/admin/notifications/dismiss', {
        item_id: id,
        fingerprint: fp,
      })
        .then(function (data) {
          applyData(data);
        })
        .catch(function () {
          showError('Échec du marquage comme lu.');
        });
    });

    if (dismissAllBtn) {
      dismissAllBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        postDismiss('/api/admin/notifications/dismiss-all', null)
          .then(function (data) {
            applyData(data);
          })
          .catch(function () {
            showError('Échec du marquage comme lu.');
          });
      });
    }

    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      setOpen(!open);
    });

    document.addEventListener('click', function (e) {
      if (!open) return;
      if (Date.now() < ignoreDocClickUntil) return;
      if (root.contains(e.target)) return;
      setOpen(false);
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && open) {
        setOpen(false);
        btn.focus();
      }
    });

    fetchFeed()
      .then(function (data) {
        cache = data;
        updateBadge(data.count || 0);
        renderShortcuts(data.shortcuts || []);
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
