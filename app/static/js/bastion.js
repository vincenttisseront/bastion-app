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
      if (!confirm(el.dataset.confirm || 'Confirmer cette action ?')) {
        e.preventDefault();
      }
    });
  });

  var search = document.getElementById('app-search');
  if (search) {
    search.addEventListener('input', function () {
      var q = search.value.toLowerCase();
      document.querySelectorAll('[data-searchable]').forEach(function (el) {
        el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

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

function initAccessModeForm() {
  var form = document.getElementById('app-form');
  if (!form) return;

  var select = form.querySelector('[data-access-mode-select]');
  var labelEl = document.getElementById('upstream-url-label');
  var helpEl = document.getElementById('upstream-url-help');
  var upstreamInput = document.getElementById('upstream_url');
  var fqdnGroup = document.getElementById('public-fqdn-group');
  var legacyWarn = document.getElementById('access-mode-legacy-warning');
  if (!select || !labelEl || !helpEl) return;

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
  }

  select.addEventListener('change', applyMode);
  applyMode();
}
