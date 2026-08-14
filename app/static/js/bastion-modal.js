/**
 * Bastion themed confirm / alert / prompt / password dialogs.
 *
 * window.bastionConfirm({ title, message, list, confirmLabel, cancelLabel, danger })
 *   → Promise<boolean>
 * window.bastionAlert({ title, message, confirmLabel })
 *   → Promise<void>
 * window.bastionPrompt({ title, message, label, defaultValue, placeholder, confirmLabel, cancelLabel, required })
 *   → Promise<string|null>  (null = cancelled)
 * window.bastionPasswordPrompt({ title, message, username, confirmLabel, cancelLabel, error, onConfirm })
 *   → Promise<{ ok: boolean, password: string|null }>
 *   Optional onConfirm(password) runs inside the click/Enter gesture before close.
 *   Return false from onConfirm to keep the modal open.
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
  var mode = 'confirm'; // confirm | alert | password | prompt
  var passwordInput = null;
  var passwordErrorEl = null;
  var promptInput = null;
  var promptErrorEl = null;
  var promptRequired = false;
  var listenersBound = false;
  var passwordOnConfirm = null;

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
      confirmFromUi();
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
    var prompt = extraEl.querySelector('#bastion-modal-prompt');
    if (prompt) prompt.value = '';
    extraEl.innerHTML = '';
    extraEl.hidden = true;
    passwordInput = null;
    passwordErrorEl = null;
    promptInput = null;
    promptErrorEl = null;
    promptRequired = false;
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
          confirmFromUi();
        }
      });
    }
  }

  function renderPromptField(options) {
    var label = options.label || 'Valeur';
    var placeholder = options.placeholder || '';
    var defaultValue = options.defaultValue || '';
    promptRequired = options.required !== false;
    extraEl.innerHTML =
      '<div class="bastion-modal-prompt-form">' +
      '<div class="form-group">' +
      '<label class="form-label" for="bastion-modal-prompt">' +
      escapeHtml(label) +
      '</label>' +
      '<input type="text" id="bastion-modal-prompt" class="form-input" ' +
      'value="' +
      escapeHtml(defaultValue) +
      '" placeholder="' +
      escapeHtml(placeholder) +
      '" autocomplete="off" autofocus>' +
      '<div id="bastion-modal-prompt-error" class="form-error" hidden></div>' +
      '</div>' +
      '</div>';
    extraEl.hidden = false;
    promptInput = document.getElementById('bastion-modal-prompt');
    promptErrorEl = document.getElementById('bastion-modal-prompt-error');
    if (promptInput) {
      promptInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          confirmFromUi();
        }
      });
    }
  }

  function showPasswordError(text) {
    passwordErrorEl = document.getElementById('bastion-modal-password-error') || passwordErrorEl;
    if (!passwordErrorEl) return;
    if (text) {
      passwordErrorEl.textContent = text;
      passwordErrorEl.hidden = false;
    } else {
      passwordErrorEl.textContent = '';
      passwordErrorEl.hidden = true;
    }
  }

  function showPromptError(text) {
    promptErrorEl = document.getElementById('bastion-modal-prompt-error') || promptErrorEl;
    if (!promptErrorEl) return;
    if (text) {
      promptErrorEl.textContent = text;
      promptErrorEl.hidden = false;
    } else {
      promptErrorEl.textContent = '';
      promptErrorEl.hidden = true;
    }
  }

  function confirmFromUi() {
    if (mode === 'password') {
      passwordInput = document.getElementById('bastion-modal-password') || passwordInput;
      var passwordValue = passwordInput ? passwordInput.value : '';
      if (!passwordValue) {
        showPasswordError('Saisissez votre mot de passe pour ouvrir cette application.');
        if (passwordInput) passwordInput.focus();
        return;
      }
      showPasswordError('');
      if (typeof passwordOnConfirm === 'function') {
        try {
          var cont = passwordOnConfirm(passwordValue);
          if (cont === false) {
            showPasswordError("Impossible d'ouvrir l'application. Réessayez.");
            return;
          }
        } catch (err) {
          showPasswordError("Impossible d'ouvrir l'application. Réessayez.");
          return;
        }
      }
      finishClose({ ok: true, password: passwordValue });
      return;
    }
    if (mode === 'prompt') {
      promptInput = document.getElementById('bastion-modal-prompt') || promptInput;
      var promptValue = promptInput ? String(promptInput.value || '') : '';
      if (promptRequired && !promptValue.trim()) {
        showPromptError('Ce champ est requis.');
        if (promptInput) promptInput.focus();
        return;
      }
      showPromptError('');
      finishClose(promptValue);
      return;
    }
    close(true);
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
    if (promptInput) promptInput.value = '';
    clearExtra();
    passwordOnConfirm = null;
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
      passwordInput = document.getElementById('bastion-modal-password') || passwordInput;
      passwordValue = result && passwordInput ? passwordInput.value : null;
    }
    if (mode === 'alert') {
      finishClose(undefined);
    } else if (mode === 'password') {
      finishClose({ ok: Boolean(result), password: passwordValue });
    } else if (mode === 'prompt') {
      finishClose(result ? (promptInput ? promptInput.value : '') : null);
    } else {
      finishClose(Boolean(result));
    }
  }

  function open(options, asAlert) {
    options = options || {};
    if (!ensureDom()) {
      if (asAlert) {
        return Promise.resolve();
      }
      return Promise.resolve(false);
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

  window.bastionPrompt = function (options) {
    options = options || {};
    if (typeof options === 'string') options = { message: options };
    if (!ensureDom()) {
      return Promise.resolve(null);
    }
    if (pendingResolve) close(false);
    mode = 'prompt';
    previousFocus = document.activeElement;
    titleEl.textContent = options.title || 'Saisie';
    messageEl.innerHTML = formatMessage(options.message || '');
    renderPromptField(options);
    confirmBtn.textContent = options.confirmLabel || 'Valider';
    confirmBtn.className = 'btn btn-secondary';
    confirmBtn.disabled = false;
    cancelBtn.hidden = false;
    cancelBtn.textContent = options.cancelLabel || 'Annuler';
    root.hidden = false;
    root.setAttribute('aria-hidden', 'false');
    root.classList.add('is-open');
    document.body.classList.add('bastion-modal-open');
    setTimeout(function () {
      promptInput = document.getElementById('bastion-modal-prompt');
      if (promptInput) {
        promptInput.focus();
        promptInput.select();
      } else confirmBtn.focus();
    }, 0);
    return new Promise(function (resolve) {
      pendingResolve = resolve;
    });
  };

  window.bastionPasswordPrompt = function (options) {
    options = options || {};
    if (!ensureDom()) {
      return Promise.resolve({ ok: false, password: null });
    }
    if (pendingResolve) close(false);
    mode = 'password';
    passwordOnConfirm = typeof options.onConfirm === 'function' ? options.onConfirm : null;
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
