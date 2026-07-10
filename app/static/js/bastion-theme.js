(function () {
  'use strict';
  var STORAGE_KEY = 'bastion-theme';
  var root = document.documentElement;

  function getPreferred() {
    var stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
    return 'dark';
  }

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.setAttribute('aria-label', theme === 'dark' ? 'Activer le thème clair' : 'Activer le thème sombre');
      btn.setAttribute('title', theme === 'dark' ? 'Thème clair' : 'Thème sombre');
    }
  }

  applyTheme(getPreferred());

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var current = root.getAttribute('data-theme') || 'dark';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });
  });
})();
