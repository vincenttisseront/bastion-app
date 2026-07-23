document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.alert.auto-close, .alert[data-dismiss]').forEach(function (el) {
    setTimeout(function () {
      el.style.transition = 'opacity .4s,max-height .4s';
      el.style.opacity = '0';
      el.style.maxHeight = '0';
      el.style.overflow = 'hidden';
      setTimeout(function () { el.remove(); }, 400);
    }, 4000);
  });

  document.querySelectorAll('.alert-close').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var alert = btn.closest('.alert');
      if (alert) alert.remove();
    });
  });

  document.querySelectorAll('[data-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      if (el.dataset.bastionConfirmOk === '1') {
        el.dataset.bastionConfirmOk = '';
        return;
      }
      e.preventDefault();
      e.stopPropagation();
      var msg = el.dataset.confirm || 'Confirmer cette action ?';
      var run = function (ok) {
        if (!ok) return;
        el.dataset.bastionConfirmOk = '1';
        if (el.tagName === 'A' || el.tagName === 'BUTTON' || el.type === 'submit') {
          el.click();
        }
      };
      if (window.bastionConfirm) {
        window.bastionConfirm({ message: msg, danger: true }).then(run);
      } else if (confirm(msg)) {
        run(true);
      }
    });
  });

  var search = document.getElementById('app-search');
  if (search && window.BastionFuzzy) {
    window.BastionFuzzy.init({
      inputId: 'app-search',
      itemSelector: '[data-searchable]',
      getKey: function (el) {
        return (el.dataset && el.dataset.fuzzyKey) || el.textContent || '';
      },
    });
  }

  // Deep-link from global search: /apps#app-{slug}
  (function highlightAppFromHash() {
    var raw = (location.hash || '').replace(/^#/, '');
    if (!raw || raw.indexOf('app-') !== 0) return;
    var tile = document.getElementById(raw);
    if (!tile || !tile.classList.contains('app-tile')) return;
    try {
      tile.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } catch (err) {
      tile.scrollIntoView(true);
    }
    tile.classList.add('app-tile--highlight');
    window.setTimeout(function () {
      tile.classList.remove('app-tile--highlight');
    }, 2000);
  })();

  var sidebarSearch = document.getElementById('sidebar-search');
  if (sidebarSearch) {
    sidebarSearch.addEventListener('input', function () {
      var q = sidebarSearch.value.toLowerCase();
      document.querySelectorAll('.nav-item, .sidebar-nav-item').forEach(function (item) {
        item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  document.querySelectorAll('.filter-chip[data-filter], .sev-chip[data-filter]').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var group = chip.closest('.filter-group, .severity-filter');
      if (group) {
        group.querySelectorAll('.filter-chip, .sev-chip').forEach(function (c) {
          c.classList.remove('active');
        });
      }
      chip.classList.add('active');
      // Catalogue (and similar): let BastionFuzzy combine text + chip filters.
      if (window.BastionFuzzy && window.BastionFuzzy.reapplyAll &&
          document.getElementById('catalogue-search')) {
        window.BastionFuzzy.reapplyAll();
        return;
      }
      var filter = chip.dataset.filter;
      document.querySelectorAll('[data-mode], [data-severity]').forEach(function (el) {
        var mode = el.dataset.mode || el.dataset.severity;
        el.style.display = filter === 'all' || mode === filter ? '' : 'none';
      });
    });
  });

  initSlugFromLabel();
  initAccessModeForm();
});

function slugify(str) {
  return str.toString().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase().trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function initSlugFromLabel() {
  document.querySelectorAll('[name="slug"][data-mode="create"]').forEach(function (slugInput) {
    var form = slugInput.closest('form');
    if (!form) return;

    var fromName = slugInput.dataset.slugFrom || 'label';
    var labelInput = form.querySelector('[name="' + fromName + '"]');
    if (!labelInput) return;

    var slugManuallyEdited = Boolean(
      slugInput.value && slugInput.value !== slugify(labelInput.value)
    );

    slugInput.addEventListener('input', function () {
      slugManuallyEdited = true;
      slugInput.classList.remove('slug-auto');
    });

    labelInput.addEventListener('input', function () {
      if (slugManuallyEdited) return;
      slugInput.value = slugify(labelInput.value);
      slugInput.classList.toggle('slug-auto', Boolean(slugInput.value));
    });

    slugInput.classList.toggle('slug-auto', Boolean(slugInput.value) && !slugManuallyEdited);
  });
}

var ACCESS_MODE_COPY = {
  sso_gate: {
    upstreamLabel: "URL publique de l'application",
    upstreamHelp: "L'utilisateur sera redirigé ici après validation SSO. Aucun proxy.",
    upstreamPlaceholder: 'https://app.example.fr/',
    showFqdn: false,
    showLegacyWarn: false
  },
  subdomain_proxy: {
    upstreamLabel: 'URL backend interne (proxy_pass)',
    upstreamHelp: 'Cible du reverse proxy Nginx sur le sous-domaine dédié.',
    upstreamPlaceholder: 'http://127.0.0.1:8080/',
    showFqdn: true,
    showLegacyWarn: false
  },
  legacy_path_proxy: {
    upstreamLabel: 'URL backend interne (proxy_pass)',
    upstreamHelp: 'Cible proxifiée sous /proxy/{slug}/ — apps compatibles sous-chemin uniquement.',
    upstreamPlaceholder: 'http://127.0.0.1:8080/',
    showFqdn: false,
    showLegacyWarn: true
  }
};

function normalizeHostname(value) {
  var raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  // URL or path-ish input → use the browser URL parser
  if (raw.indexOf('://') !== -1 || raw.indexOf('/') !== -1 || raw.indexOf('?') !== -1 || raw.indexOf('#') !== -1) {
    try {
      var href = raw.indexOf('://') !== -1 ? raw : ('https://' + raw);
      var host = new URL(href).hostname || '';
      return host.replace(/^\.+|\.+$/g, '');
    } catch (e) {
      /* fall through */
    }
  }
  raw = raw.replace(/^\.+|\.+$/g, '');
  // host:port (not IPv6)
  var portMatch = raw.match(/^([^:]+):(\d+)$/);
  if (portMatch) return portMatch[1];
  return raw;
}

function sharedParentDomain(fqdn, portalDomain) {
  var fqdnLabels = normalizeHostname(fqdn).split('.');
  var portalLabels = normalizeHostname(portalDomain).split('.');
  if (!fqdnLabels[0] || !portalLabels[0]) return null;
  var common = [];
  var i = 0;
  while (
    i < fqdnLabels.length &&
    i < portalLabels.length &&
    fqdnLabels[fqdnLabels.length - 1 - i] === portalLabels[portalLabels.length - 1 - i]
  ) {
    common.push(fqdnLabels[fqdnLabels.length - 1 - i]);
    i += 1;
  }
  if (common.length < 2) return null;
  return common.reverse().join('.');
}

// Exported for unit tests / console checks
window.bastionNormalizeHostname = normalizeHostname;
window.bastionSharedParentDomain = sharedParentDomain;

function initAccessModeForm() {
  var form = document.getElementById('app-form');
  if (!form) return;

  var select = form.querySelector('[data-access-mode-select]');
  var labelEl = document.getElementById('upstream-url-label');
  var helpEl = document.getElementById('upstream-url-help');
  var upstreamInput = document.getElementById('upstream_url');
  var fqdnGroup = document.getElementById('public-fqdn-group');
  var fqdnInput = document.getElementById('public_fqdn');
  var fqdnCookieWarn = document.getElementById('fqdn-cookie-domain-warning');
  var legacyWarn = document.getElementById('access-mode-legacy-warning');
  var authSection = document.getElementById('auth-mode-section');
  var authSelect = document.querySelector('[data-auth-mode-select]');
  var genericFields = document.getElementById('generic-form-fields');
  var wsseHelp = document.getElementById('generic-wsse-help');
  if (!select || !labelEl || !helpEl) return;

  function syncFqdnCookieWarning() {
    if (!fqdnCookieWarn || !fqdnInput) return;
    var mode = select.value;
    var fqdn = (fqdnInput.value || '').trim();
    var portalDomain = fqdnInput.getAttribute('data-portal-domain') || '';
    var show =
      mode === 'subdomain_proxy' &&
      fqdn.length > 0 &&
      !sharedParentDomain(fqdn, portalDomain);
    fqdnCookieWarn.hidden = !show;
  }

  function applyMode() {
    var mode = select.value;
    var copy = ACCESS_MODE_COPY[mode] || ACCESS_MODE_COPY.sso_gate;
    labelEl.innerHTML = copy.upstreamLabel + ' <span class="req">*</span>';
    helpEl.textContent = copy.upstreamHelp;
    if (upstreamInput && copy.upstreamPlaceholder) {
      upstreamInput.placeholder = copy.upstreamPlaceholder;
    }
    if (fqdnGroup) fqdnGroup.hidden = !copy.showFqdn;
    if (legacyWarn) legacyWarn.hidden = !copy.showLegacyWarn;
    if (authSection) {
      authSection.hidden = (mode === 'sso_gate');
    }
    syncFqdnCookieWarning();
  }

  function applyAuthMode() {
    if (!authSelect) return;
    var mode = authSelect.value;
    // generic_form only — keep hidden for generic_basic_auth and generic_wsse
    if (genericFields) {
      genericFields.hidden = (mode !== 'generic_form');
    }
    if (wsseHelp) {
      wsseHelp.hidden = (mode !== 'generic_wsse');
    }
  }

  select.addEventListener('change', applyMode);
  applyMode();
  if (fqdnInput) {
    fqdnInput.addEventListener('input', syncFqdnCookieWarning);
    fqdnInput.addEventListener('change', syncFqdnCookieWarning);
  }
  if (authSelect) {
    authSelect.addEventListener('change', applyAuthMode);
    applyAuthMode();
  }
}
