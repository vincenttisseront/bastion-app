(function () {
  'use strict';
  var STORAGE_KEY = 'bp-theme';
  var LEGACY_KEY = 'bastion-theme';
  var PREF_KEY = 'bp-theme-pref';
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

  function getPreference() {
    var pref = localStorage.getItem(PREF_KEY);
    if (pref === 'light' || pref === 'dark' || pref === 'system') return pref;
    // Migrate legacy absolute theme storage.
    var legacy = localStorage.getItem(STORAGE_KEY) || localStorage.getItem(LEGACY_KEY);
    if (legacy === 'light' || legacy === 'dark') return legacy;
    return 'dark';
  }

  function resolveTheme(pref) {
    if (pref === 'system') {
      return media && media.matches ? 'light' : 'dark';
    }
    return pref === 'light' ? 'light' : 'dark';
  }

  function applyResolved(theme) {
    root.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
    localStorage.setItem(LEGACY_KEY, theme);
    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.setAttribute(
        'aria-label',
        theme === 'dark' ? 'Activer le thème clair' : 'Activer le thème sombre'
      );
    }
  }

  function setPreference(pref) {
    if (pref !== 'light' && pref !== 'dark' && pref !== 'system') pref = 'dark';
    localStorage.setItem(PREF_KEY, pref);
    applyResolved(resolveTheme(pref));
  }

  function toggleAbsolute() {
    var pref = getPreference();
    if (pref === 'system') {
      setPreference(resolveTheme('system') === 'dark' ? 'light' : 'dark');
      return;
    }
    setPreference(pref === 'dark' ? 'light' : 'dark');
  }

  // Apply ASAP to avoid FOUC.
  applyResolved(resolveTheme(getPreference()));

  if (media && typeof media.addEventListener === 'function') {
    media.addEventListener('change', function () {
      if (getPreference() === 'system') {
        applyResolved(resolveTheme('system'));
      }
    });
  }

  window.BastionTheme = {
    getPreference: getPreference,
    setPreference: setPreference,
    resolveTheme: resolveTheme,
    toggle: toggleAbsolute,
  };

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      toggleAbsolute();
    });
  });
})();
