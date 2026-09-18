(function () {
  'use strict';

  var STORAGE_KEY = 'bp-locale';
  var COOKIE_NAME = 'portal_locale';
  var SUPPORTED = { fr: true, en: true };
  var COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

  function readCookie(name) {
    var parts = (' ' + (document.cookie || '')).split(';');
    var prefix = name + '=';
    for (var part of parts) {
      var p = part.trim();
      if (p.startsWith(prefix)) {
        return decodeURIComponent(p.slice(prefix.length));
      }
    }
    return null;
  }

  function writeCookie(name, value) {
    var parts = [
      name + '=' + encodeURIComponent(value),
      'Path=/',
      'Max-Age=' + COOKIE_MAX_AGE,
      'SameSite=Lax',
    ];
    if (window.location.protocol === 'https:') {
      parts.push('Secure');
    }
    document.cookie = parts.join('; ');
  }

  function normalize(value) {
    if (!value) return null;
    var primary = String(value).toLowerCase().replace('_', '-').split('-')[0];
    return SUPPORTED[primary] ? primary : null;
  }

  function getLocale() {
    // Prefer what the server rendered so the toggle matches SSR text.
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
    writeCookie(COOKIE_NAME, loc);
    window.__locale = loc;

    var next = nextUrl || window.location.pathname + window.location.search + window.location.hash;
    var body = new FormData();
    body.append('locale', loc);
    body.append('next', next);

    var headers = { Accept: 'application/json' };
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta?.content) {
      headers['X-CSRF-Token'] = csrfMeta.content;
      body.append('csrf_token', csrfMeta.content);
    }

    // Best-effort server cookie sync; navigate even if fetch fails (cookie already set).
    var done = false;
    function go() {
      if (done) return;
      done = true;
      window.location.assign(next);
    }
    fetch('/api/locale', {
      method: 'POST',
      body: body,
      credentials: 'same-origin',
      headers: headers,
      redirect: 'manual',
    }).then(go).catch(go);
    setTimeout(go, 1500);
  }

  function syncToggle() {
    var locale = getLocale();
    document.documentElement.setAttribute('lang', locale);
    var buttons = document.querySelectorAll('[data-locale-toggle]');
    for (var btn of buttons) {
      var target = btn.dataset.localeToggle;
      var active = target === locale;
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
      btn.classList.toggle('is-active', active);
      if (btn.type === 'radio' || btn.type === 'checkbox') {
        btn.checked = active;
      }
    }
    var selects = document.querySelectorAll('[data-locale-select]');
    for (var select of selects) {
      select.value = locale;
    }
  }

  function localeFromControl(el) {
    if (!el) return null;
    return el.dataset.localeToggle || el.value || null;
  }

  function isNativeLocaleSubmit(el) {
    // Login/profile use real POST forms — do not intercept.
    if (!el || el.tagName !== 'BUTTON') return false;
    if ((el.getAttribute('type') || '').toLowerCase() === 'submit') return true;
    var form = el.form || el.closest('form');
    return form?.getAttribute('action') === '/api/locale';
  }

  function bindControls() {
    document.addEventListener('click', function (ev) {
      var btn = ev.target.closest('[data-locale-toggle]');
      if (!btn) return;
      if (btn.type === 'radio' || btn.type === 'checkbox') return;
      if (isNativeLocaleSubmit(btn)) return;
      ev.preventDefault();
      var target = localeFromControl(btn);
      if (target && target !== getLocale()) setLocale(target);
    });
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

  var serverLocale = normalize(window.__locale);
  if (serverLocale && !normalize(readCookie(COOKIE_NAME))) {
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
