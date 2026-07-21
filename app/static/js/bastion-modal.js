/**
 * Bastion themed confirm / alert / password dialogs.
 *
 * window.bastionConfirm({ title, message, list, confirmLabel, cancelLabel, danger })
 *   → Promise<boolean>
 * window.bastionAlert({ title, message, confirmLabel })
 *   → Promise<void>
 * window.bastionPasswordPrompt({ title, message, username, confirmLabel, cancelLabel, error })
 *   → Promise<{ ok: boolean, password: string|null }>
 *
 * Confirm / dismiss use document-level event delegation so handlers work even if
 * the modal markup is re-rendered or scripts load before the partial is present.
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
  var mode = 'confirm'; // confirm | alert | password
  var passwordInput = null;
  var passwordErrorEl = null;
  var listenersBound = false;

  function refreshRefs() {
    root = document.getElementById('bastion-modal');
    if (!root) return false;
    titleEl = document.getElementById('bastion-modal-title');
    messageEl = document.getElementById('bastion-modal-message');
    extraEl = document.getElementById('bastion-modal-extra');
    cancelBtn = document.getElementById('bastion-modal-cancel');
    confirmBtn = document.getElementById('bastion-modal-confirm');
    dialogEl = root.querySelector('.bastion-modal-dialog');
    return Boolean(titleEl && messageEl && extraEl && cancelBtn && confirmBtn);
  }

  function ensureDom() {
    if (!refreshRefs()) return false;
    if (!listenersBound) {
      document.addEventListener('click', onDocumentClick, true);
      document.addEventListener('keydown', onKeyDown, true);
      listenersBound = true;
    }
    return true;
  }

  function onDocumentClick(e) {
    if (!root || root.hidden) return;
    var target = e.target;
    if (!target || typeof target.closest !== 'function') return;
    if (!root.contains(target)) return;

    if (target.closest('[data-bastion-modal-dismiss]')) {
      e.preventDefault();
      e.stopPropagation();
      close(false);
      return;
    }

    if (target.closest('#bastion-modal-confirm')) {
      e.preventDefault();
      e.stopPropagation();
      close(true);
    }
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

  function clearExtra() {
    if (!extraEl) return;
    var pass = extraEl.querySelector('#bastion-modal-password');
    if (pass) pass.value = '';
    extraEl.innerHTML = '';
    extraEl.hidden = true;
    passwordInput = null;
    passwordErrorEl = null;
  }

  function renderList(list) {
    if (!list || !list.length) {
      clearExtra();
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

  function renderPasswordFields(username, errorText) {
    extraEl.innerHTML =
      '<div class="bastion-modal-password-form">' +
      '<div class="form-group" style="margin-bottom:var(--sp-3);">' +
      '<label class="form-label" for="bastion-modal-username">Identifiant</label>' +
      '<input type="text" id="bastion-modal-username" class="form-input" readonly ' +
      'value="' +
      escapeHtml(username || '') +
      '" autocomplete="username">' +
      '</div>' +
      '<div class="form-group">' +
      '<label class="form-label" for="bastion-modal-password">Mot de passe</label>' +
      '<input type="password" id="bastion-modal-password" class="form-input" ' +
      'autocomplete="off" autofocus>' +
      '<p class="form-help" style="margin-top:var(--sp-2);">' +
      'Transmis uniquement pour cette connexion, non conservé.' +
      '</p>' +
      '<div id="bastion-modal-password-error" class="form-error bastion-modal-password-error"' +
      (errorText ? '' : ' hidden') +
      '>' +
      escapeHtml(errorText || '') +
      '</div>' +
      '</div>' +
      '</div>';
    extraEl.hidden = false;
    passwordInput = document.getElementById('bastion-modal-password');
    passwordErrorEl = document.getElementById('bastion-modal-password-error');
    if (passwordInput) {
      passwordInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          close(true);
        }
      });
    }
  }

  function focusables() {
    if (!dialogEl) return [];
    return Array.prototype.slice
      .call(
        dialogEl.querySelectorAll(
          'button:not([disabled]):not([hidden]), [href], input:not([disabled]):not([readonly]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
      )
      .filter(function (el) {
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

  function finishClose(payload) {
    if (root) {
      root.hidden = true;
      root.setAttribute('aria-hidden', 'true');
      root.classList.remove('is-open');
    }
    document.body.classList.remove('bastion-modal-open');
    if (passwordInput) passwordInput.value = '';
    clearExtra();
    if (confirmBtn) confirmBtn.disabled = false;
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
    if (resolve) resolve(payload);
  }

  function close(result) {
    if (!root || root.hidden) return;
    var passwordValue = null;
    if (mode === 'password') {
      // Re-query in case refs went stale after innerHTML updates
      passwordInput = document.getElementById('bastion-modal-password') || passwordInput;
      passwordValue = result && passwordInput ? passwordInput.value : null;
    }
    if (mode === 'alert') {
      finishClose(undefined);
    } else if (mode === 'password') {
      finishClose({ ok: Boolean(result), password: passwordValue });
    } else {
      finishClose(Boolean(result));
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
    confirmBtn.disabled = false;
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

  window.bastionPasswordPrompt = function (options) {
    options = options || {};
    if (!ensureDom()) {
      return Promise.resolve({ ok: false, password: null });
    }
    if (pendingResolve) close(false);
    mode = 'password';
    previousFocus = document.activeElement;
    titleEl.textContent = options.title || 'Mot de passe requis';
    messageEl.innerHTML = formatMessage(
      options.message || 'Saisissez votre mot de passe pour ouvrir cette application.'
    );
    renderPasswordFields(options.username || '', options.error || '');
    confirmBtn.textContent = options.confirmLabel || 'Ouvrir';
    confirmBtn.className = 'btn btn-secondary';
    confirmBtn.disabled = false;
    cancelBtn.hidden = false;
    cancelBtn.textContent = options.cancelLabel || 'Annuler';
    root.hidden = false;
    root.setAttribute('aria-hidden', 'false');
    root.classList.add('is-open');
    document.body.classList.add('bastion-modal-open');
    setTimeout(function () {
      passwordInput = document.getElementById('bastion-modal-password');
      if (passwordInput) passwordInput.focus();
      else confirmBtn.focus();
    }, 0);
    return new Promise(function (resolve) {
      pendingResolve = resolve;
    });
  };
})();
