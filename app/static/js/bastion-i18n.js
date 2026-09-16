(function () {
  'use strict';

  var STORAGE_KEY = 'bp-locale';
  var COOKIE_NAME = 'portal_locale';
  var SUPPORTED = { fr: true, en: true };

  function readCookie(name) {
    var parts = ('; ' + (document.cookie || '')).split(';');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (p.indexOf(name + '=') === 0) {
        return decodeURIComponent(p.slice(name.length + 1));
      }
    }
    return null;
  }

  function normalize(value) {
    if (!value) return null;
    var primary = String(value).toLowerCase().replace('_', '-').split('-')[0];
    return SUPPORTED[primary] ? primary : null;
  }

  function getLocale() {
    return (
      normalize(window.__locale) ||
      normalize(readCookie(COOKIE_NAME)) ||
      normalize(localStorage.getItem(STORAGE_KEY)) ||
      'fr'
    );
  }

  function t(msgid) {
    if (!msgid) return '';
    var locale = getLocale();
    if (locale === 'fr') return String(msgid);
    var catalog = window.__i18n || {};
    return catalog[msgid] || String(msgid);
  }

  function setLocale(locale, nextUrl) {
    var loc = normalize(locale) || 'fr';
    localStorage.setItem(STORAGE_KEY, loc);
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/api/locale';
    form.style.display = 'none';

    var localeInput = document.createElement('input');
    localeInput.type = 'hidden';
    localeInput.name = 'locale';
    localeInput.value = loc;
    form.appendChild(localeInput);

    var nextInput = document.createElement('input');
    nextInput.type = 'hidden';
    nextInput.name = 'next';
    nextInput.value = nextUrl || window.location.pathname + window.location.search;
    form.appendChild(nextInput);

    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta && csrfMeta.content) {
      var csrfInput = document.createElement('input');
      csrfInput.type = 'hidden';
      csrfInput.name = 'csrf_token';
      csrfInput.value = csrfMeta.content;
      form.appendChild(csrfInput);
    }

    document.body.appendChild(form);
    form.submit();
  }

  function syncToggle() {
    var locale = getLocale();
    document.documentElement.setAttribute('lang', locale);
    var buttons = document.querySelectorAll('[data-locale-toggle]');
    for (var i = 0; i < buttons.length; i++) {
      var btn = buttons[i];
      var target = btn.getAttribute('data-locale-toggle');
      var active = target === locale;
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
      btn.classList.toggle('is-active', active);
      // Profile uses radios inside labels — keep checked state in sync.
      if (btn.type === 'radio' || btn.type === 'checkbox') {
        btn.checked = active;
      }
    }
    var selects = document.querySelectorAll('[data-locale-select]');
    for (var j = 0; j < selects.length; j++) {
      selects[j].value = locale;
    }
  }

  function localeFromControl(el) {
    if (!el) return null;
    return el.getAttribute('data-locale-toggle') || el.value || null;
  }

  function bindControls() {
    // Buttons (login FR/EN): click target has data-locale-toggle.
    document.addEventListener('click', function (ev) {
      var btn = ev.target.closest('[data-locale-toggle]');
      if (!btn) return;
      // Radios/checkboxes: native label click checks them; handle via change.
      if (btn.type === 'radio' || btn.type === 'checkbox') return;
      ev.preventDefault();
      var target = localeFromControl(btn);
      if (target && target !== getLocale()) setLocale(target);
    });
    // Profile radios + selects: fire on change (covers label clicks).
    document.addEventListener('change', function (ev) {
      var el = ev.target.closest('[data-locale-toggle], [data-locale-select]');
      if (!el) return;
      var target = localeFromControl(el);
      if (target && target !== getLocale()) setLocale(target);
    });
  }

  window.BastionI18n = {
    t: t,
    getLocale: getLocale,
    setLocale: setLocale,
    syncToggle: syncToggle,
  };

  // Mirror server locale into localStorage when present.
  var serverLocale = normalize(window.__locale);
  if (serverLocale) {
    localStorage.setItem(STORAGE_KEY, serverLocale);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      syncToggle();
      bindControls();
    });
  } else {
    syncToggle();
    bindControls();
  }
})();
