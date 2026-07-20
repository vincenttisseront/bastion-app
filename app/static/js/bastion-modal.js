/**
 * Bastion themed confirm / alert dialogs (replaces window.confirm / window.alert).
 *
 * window.bastionConfirm({ title, message, list, confirmLabel, cancelLabel, danger })
 *   → Promise<boolean>
 * window.bastionAlert({ title, message, confirmLabel })
 *   → Promise<void>
 */
(function () {
  'use strict';

  var root = null;
  var titleEl = null;
  var messageEl = null;
  var extraEl = null;
  var cancelBtn = null;
  var confirmBtn = null;
  var dialogEl = null;
  var pendingResolve = null;
  var previousFocus = null;
  var mode = 'confirm'; // confirm | alert

  function ensureDom() {
    if (root) return true;
    root = document.getElementById('bastion-modal');
    if (!root) return false;
    titleEl = document.getElementById('bastion-modal-title');
    messageEl = document.getElementById('bastion-modal-message');
    extraEl = document.getElementById('bastion-modal-extra');
    cancelBtn = document.getElementById('bastion-modal-cancel');
    confirmBtn = document.getElementById('bastion-modal-confirm');
    dialogEl = root.querySelector('.bastion-modal-dialog');
    root.querySelectorAll('[data-bastion-modal-dismiss]').forEach(function (el) {
      el.addEventListener('click', function () {
        close(false);
      });
    });
    confirmBtn.addEventListener('click', function () {
      close(true);
    });
    document.addEventListener('keydown', onKeyDown);
    return true;
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatMessage(text) {
    return escapeHtml(text || '').replace(/\n/g, '<br>');
  }

  function renderList(list) {
    if (!list || !list.length) {
      extraEl.hidden = true;
      extraEl.innerHTML = '';
      return;
    }
    var items = list
      .map(function (item) {
        if (item && typeof item === 'object') {
          var label = escapeHtml(item.label || item.name || '');
          var detail = escapeHtml(item.detail || item.fqdn || item.subtitle || '');
          return (
            '<li><span class="bastion-modal-list-label">' +
            label +
            '</span>' +
            (detail
              ? ' <span class="mono bastion-modal-list-detail">' + detail + '</span>'
              : '') +
            '</li>'
          );
        }
        return '<li>' + escapeHtml(item) + '</li>';
      })
      .join('');
    extraEl.innerHTML = '<ul class="bastion-modal-list">' + items + '</ul>';
    extraEl.hidden = false;
  }

  function focusables() {
    if (!dialogEl) return [];
    return Array.prototype.slice.call(
      dialogEl.querySelectorAll(
        'button:not([disabled]):not([hidden]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    ).filter(function (el) {
      return el.offsetParent !== null || el === document.activeElement;
    });
  }

  function onKeyDown(e) {
    if (!root || root.hidden) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      close(false);
      return;
    }
    if (e.key !== 'Tab') return;
    var nodes = focusables();
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

  function close(result) {
    if (!root || root.hidden) return;
    root.hidden = true;
    root.setAttribute('aria-hidden', 'true');
    root.classList.remove('is-open');
    document.body.classList.remove('bastion-modal-open');
    if (previousFocus && typeof previousFocus.focus === 'function') {
      try {
        previousFocus.focus();
      } catch (err) {
        /* ignore */
      }
    }
    previousFocus = null;
    var resolve = pendingResolve;
    pendingResolve = null;
    if (resolve) {
      if (mode === 'alert') resolve();
      else resolve(Boolean(result));
    }
  }

  function open(options, asAlert) {
    options = options || {};
    if (!ensureDom()) {
      if (asAlert) {
        window.alert(options.message || '');
        return Promise.resolve();
      }
      return Promise.resolve(window.confirm(options.message || options.title || 'Confirmer ?'));
    }
    if (pendingResolve) {
      close(false);
    }
    mode = asAlert ? 'alert' : 'confirm';
    previousFocus = document.activeElement;
    titleEl.textContent = options.title || (asAlert ? 'Information' : 'Confirmation');
    messageEl.innerHTML = formatMessage(options.message || '');
    renderList(options.list);
    confirmBtn.textContent = options.confirmLabel || (asAlert ? 'OK' : 'Confirmer');
    confirmBtn.className = 'btn ' + (options.danger && !asAlert ? 'btn-danger' : 'btn-secondary');
    if (asAlert) {
      cancelBtn.hidden = true;
    } else {
      cancelBtn.hidden = false;
      cancelBtn.textContent = options.cancelLabel || 'Annuler';
    }
    root.hidden = false;
    root.setAttribute('aria-hidden', 'false');
    root.classList.add('is-open');
    document.body.classList.add('bastion-modal-open');
    setTimeout(function () {
      if (asAlert) confirmBtn.focus();
      else cancelBtn.focus();
    }, 0);
    return new Promise(function (resolve) {
      pendingResolve = resolve;
    });
  }

  window.bastionConfirm = function (options) {
    return open(options, false);
  };

  window.bastionAlert = function (options) {
    if (typeof options === 'string') options = { message: options };
    return open(options || {}, true);
  };
})();
