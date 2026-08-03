(function () {
  'use strict';

  function showPanel(root, name) {
    var panels = root.querySelectorAll('[data-login-panel]');
    var target = null;
    for (var i = 0; i < panels.length; i++) {
      var panel = panels[i];
      var match = panel.getAttribute('data-login-panel') === name;
      if (match) {
        panel.hidden = false;
        target = panel;
      } else {
        panel.hidden = true;
      }
    }
    root.setAttribute('data-active-panel', name);
    if (!target) return;
    var focusable = target.querySelector(
      'input:not([type="hidden"]):not([disabled]), button.login-sso-cta, a.login-sso-cta'
    );
    if (focusable && typeof focusable.focus === 'function') {
      try {
        focusable.focus({ preventScroll: true });
      } catch (e) {
        focusable.focus();
      }
    }
  }

  function bindPasswordToggles(root) {
    var toggles = root.querySelectorAll('[data-password-toggle]');
    for (var i = 0; i < toggles.length; i++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          var id = btn.getAttribute('data-password-toggle');
          var input = id ? document.getElementById(id) : null;
          if (!input) return;
          var show = input.type === 'password';
          input.type = show ? 'text' : 'password';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
          btn.setAttribute(
            'aria-label',
            show ? 'Masquer le mot de passe' : 'Afficher le mot de passe'
          );
        });
      })(toggles[i]);
    }
  }

  function bindPanelSwitch(root) {
    root.addEventListener('click', function (event) {
      var btn = event.target.closest('[data-login-show]');
      if (!btn || !root.contains(btn)) return;
      event.preventDefault();
      showPanel(root, btn.getAttribute('data-login-show') || 'sso');
    });
  }

  function enhanceForms(root) {
    var forms = root.querySelectorAll('form.login-form');
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        form.addEventListener('submit', function () {
          var submit = form.querySelector('button[type="submit"]');
          if (submit && !submit.disabled) {
            submit.disabled = true;
            submit.setAttribute('aria-busy', 'true');
          }
        });
      })(forms[i]);
    }
  }

  function init() {
    var root = document.querySelector('[data-login-root]');
    if (!root) return;
    var initial = root.getAttribute('data-initial-panel') || 'sso';
    showPanel(root, initial);
    bindPanelSwitch(root);
    bindPasswordToggles(root);
    enhanceForms(root);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
