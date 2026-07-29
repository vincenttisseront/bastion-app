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
  initLoginFormAnalyzer();
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
    fqdnLabel: 'Sous-domaine public',
    showFqdn: false,
    showLegacyWarn: false,
    showPublicWarn: false
  },
  subdomain_proxy: {
    upstreamLabel: 'URL backend interne (proxy_pass)',
    upstreamHelp: 'Cible du reverse proxy Nginx sur le sous-domaine dédié.',
    upstreamPlaceholder: 'http://127.0.0.1:8080/',
    fqdnLabel: 'Sous-domaine public',
    showFqdn: true,
    showLegacyWarn: false,
    showPublicWarn: false
  },
  legacy_path_proxy: {
    upstreamLabel: 'URL backend interne (proxy_pass)',
    upstreamHelp: 'Cible proxifiée sous /proxy/{slug}/ — apps compatibles sous-chemin uniquement.',
    upstreamPlaceholder: 'http://127.0.0.1:8080/',
    fqdnLabel: 'Sous-domaine public',
    showFqdn: false,
    showLegacyWarn: true,
    showPublicWarn: false
  },
  public_proxy: {
    upstreamLabel: 'URL backend interne (proxy_pass)',
    upstreamHelp: 'Cible du reverse proxy Nginx — aucune authentification bastion.',
    upstreamPlaceholder: 'http://127.0.0.1:8080/',
    fqdnLabel: 'Domaine public dédié',
    showFqdn: true,
    showLegacyWarn: false,
    showPublicWarn: true
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
  var fqdnLabelEl = document.getElementById('public-fqdn-label');
  var fqdnCookieWarn = document.getElementById('fqdn-cookie-domain-warning');
  var legacyWarn = document.getElementById('access-mode-legacy-warning');
  var publicWarn = document.getElementById('access-mode-public-warning');
  var rbacWarn = document.getElementById('access-mode-public-rbac-warning');
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
    if (fqdnLabelEl) {
      fqdnLabelEl.innerHTML = copy.fqdnLabel + ' <span class="req">*</span>';
    }
    var easWrap = document.getElementById('allow-activesync-wrap');
    var easHelp = document.getElementById('allow-activesync-help');
    var showEas = mode === 'subdomain_proxy';
    if (easWrap) easWrap.hidden = !showEas;
    if (easHelp) easHelp.hidden = !showEas;
    if (legacyWarn) legacyWarn.hidden = !copy.showLegacyWarn;
    if (publicWarn) publicWarn.hidden = !copy.showPublicWarn;
    if (rbacWarn) rbacWarn.hidden = !copy.showPublicWarn;
    if (authSection) {
      authSection.hidden = (mode === 'sso_gate' || mode === 'public_proxy');
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

function initLoginFormAnalyzer() {
  var urlInput = document.getElementById('login_form_url');
  var analyzeBtn = document.getElementById('btn-analyze-login-form');
  var panel = document.getElementById('login-form-analyze-panel');
  if (!urlInput || !analyzeBtn || !panel) return;

  var userInput = document.getElementById('login_username_field');
  var passInput = document.getElementById('login_password_field');
  var methodSelect = document.getElementById('login_http_method');
  var methodHint = document.getElementById('login-http-method-hint');
  var extraInput = document.getElementById('login_extra_fields');
  var lastResult = null;

  function isValidHttpUrl(value) {
    try {
      var u = new URL((value || '').trim());
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch (e) {
      return false;
    }
  }

  function syncAnalyzeButton() {
    analyzeBtn.disabled = !isValidHttpUrl(urlInput.value);
  }

  function markAutodetected(el, on) {
    if (!el) return;
    el.classList.toggle('is-autodetected', !!on);
  }

  function clearAutodetected() {
    markAutodetected(userInput, false);
    markAutodetected(passInput, false);
    markAutodetected(methodSelect, false);
    markAutodetected(extraInput, false);
    if (methodHint) {
      methodHint.hidden = true;
      methodHint.textContent = '';
    }
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function parseExtraJson() {
    var raw = (extraInput && extraInput.value || '').trim();
    if (!raw) return {};
    try {
      var obj = JSON.parse(raw);
      return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
    } catch (e) {
      return {};
    }
  }

  function writeExtraJson(obj) {
    if (!extraInput) return;
    var keys = Object.keys(obj);
    extraInput.value = keys.length ? JSON.stringify(obj, null, 2) : '';
    markAutodetected(extraInput, keys.length > 0);
  }

  function syncHiddenExtrasFromChecks() {
    if (!lastResult || !lastResult._appliedForm) return;
    var form = lastResult._appliedForm;
    var extras = parseExtraJson();
    (form.hidden_fields || []).forEach(function (hf) {
      var cb = panel.querySelector('[data-hidden-extra="' + CSS.escape(hf.name) + '"]');
      if (!cb) return;
      if (cb.checked) extras[hf.name] = hf.value;
      else delete extras[hf.name];
    });
    writeExtraJson(extras);
  }

  function applyForm(form, enteredUrl) {
    lastResult = lastResult || {};
    lastResult._appliedForm = form;
    clearAutodetected();

    if (form.username_field && form.username_field.name && userInput) {
      userInput.value = form.username_field.name;
      markAutodetected(userInput, true);
    }
    if (form.password_field && form.password_field.name && passInput) {
      passInput.value = form.password_field.name;
      markAutodetected(passInput, true);
    }
    if (methodSelect) {
      var method = (form.method || 'POST').toUpperCase();
      if (method === 'GET' || method === 'POST') {
        methodSelect.value = method;
        markAutodetected(methodSelect, true);
      }
      if (methodHint) {
        if (!form.method_explicit) {
          methodHint.hidden = false;
          methodHint.textContent =
            'Méthode non explicite dans le HTML — POST supposé par convention (défaut vault). Vérifiez avant d\'enregistrer.';
        } else {
          methodHint.hidden = true;
          methodHint.textContent = '';
        }
      }
    }

    var html = '';
    html += '<p class="analyze-status alert alert-ok" style="margin:0 0 var(--sp-2)">';
    html += 'Auto-détecté — vérifiez avant d\'enregistrer.';
    html += '</p>';

    if (form.username_field == null) {
      html += '<p class="form-help" style="color:var(--warn)">Champ utilisateur non détecté — renseignez-le manuellement.</p>';
    }

    var action = form.action || '';
    var entered = (enteredUrl || urlInput.value || '').trim();
    if (action && entered && action !== entered) {
      html += '<p class="form-help">Action détectée : <span class="mono">' + escapeHtml(action) + '</span></p>';
      html += '<button type="button" class="btn btn-secondary btn-sm" data-use-detected-action="' +
        escapeHtml(action) + '">Utiliser l\'URL détectée à la place</button>';
    }

    var hidden = form.hidden_fields || [];
    if (hidden.length) {
      html += '<p class="form-help" style="margin-top:var(--sp-3)">Champs cachés détectés. ';
      html += 'Un token CSRF dynamique ne doit <strong>pas</strong> être ajouté ici — ';
      html += 'le driver le récupère déjà automatiquement à chaque tentative via un GET préalable. ';
      html += 'N\'ajoutez ici que des champs à valeur fixe (ex. <span class="mono">remember=1</span>).</p>';
      html += '<ul class="analyze-hidden-list">';
      hidden.forEach(function (hf) {
        var checked = hf.likely_dynamic ? '' : ' checked';
        html += '<li>';
        html += '<label class="form-check" style="margin:0">';
        html += '<input type="checkbox" data-hidden-extra="' + escapeHtml(hf.name) + '"' + checked + '> ';
        html += 'Ajouter aux champs supplémentaires';
        html += '</label>';
        html += ' <span class="mono">' + escapeHtml(hf.name) + '</span>=';
        html += '<span class="mono">' + escapeHtml(hf.value) + '</span>';
        if (hf.likely_dynamic) {
          html += ' <span class="badge badge-warn">probablement dynamique</span>';
        }
        html += '</li>';
      });
      html += '</ul>';
    }

    panel.innerHTML = html;
    panel.hidden = false;

    // Apply default checkbox state to extra fields
    var extras = parseExtraJson();
    hidden.forEach(function (hf) {
      if (!hf.likely_dynamic) extras[hf.name] = hf.value;
      else delete extras[hf.name];
    });
    writeExtraJson(extras);

    panel.querySelectorAll('[data-hidden-extra]').forEach(function (cb) {
      cb.addEventListener('change', syncHiddenExtrasFromChecks);
    });
    var useBtn = panel.querySelector('[data-use-detected-action]');
    if (useBtn) {
      useBtn.addEventListener('click', function () {
        urlInput.value = useBtn.getAttribute('data-use-detected-action') || '';
        syncAnalyzeButton();
        useBtn.remove();
      });
    }
  }

  function showFormPicker(forms, enteredUrl) {
    var html = '<p class="analyze-status">Plusieurs formulaires avec mot de passe détectés — choisissez lequel appliquer :</p>';
    forms.forEach(function (form, idx) {
      var label =
        '#' + (idx + 1) + ' — ' + (form.field_count || '?') + ' champs, action ' +
        (form.action || '(page)');
      html +=
        '<button type="button" class="btn btn-secondary btn-sm analyze-form-choice" data-form-idx="' +
        idx +
        '">' +
        escapeHtml(label) +
        '</button>';
    });
    panel.innerHTML = html;
    panel.hidden = false;
    panel.querySelectorAll('[data-form-idx]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var idx = parseInt(btn.getAttribute('data-form-idx'), 10);
        applyForm(forms[idx], enteredUrl);
      });
    });
  }

  analyzeBtn.addEventListener('click', async function () {
    var url = (urlInput.value || '').trim();
    if (!isValidHttpUrl(url)) return;
    clearAutodetected();
    analyzeBtn.disabled = true;
    panel.hidden = false;
    panel.innerHTML = '<p class="analyze-status form-help">Analyse en cours…</p>';
    try {
      var resp = await fetch('/admin/apps/analyze-login-form', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || '',
        },
        body: JSON.stringify({ url: url }),
      });
      var data = await resp.json().catch(function () {
        return {};
      });
      if (!resp.ok) {
        panel.innerHTML =
          '<div class="alert alert-warn"><div class="alert-body">' +
          escapeHtml(data.message || data.detail || 'Analyse impossible.') +
          '</div></div>';
        return;
      }
      lastResult = data;
      var forms = data.forms || [];
      if (forms.length === 1) {
        applyForm(forms[0], url);
      } else if (forms.length > 1) {
        showFormPicker(forms, url);
      } else {
        panel.innerHTML =
          '<div class="alert alert-warn"><div class="alert-body">Aucun formulaire détecté.</div></div>';
      }
    } catch (e) {
      panel.innerHTML =
        '<div class="alert alert-err"><div class="alert-body">Erreur réseau pendant l\'analyse.</div></div>';
    } finally {
      syncAnalyzeButton();
    }
  });

  urlInput.addEventListener('input', syncAnalyzeButton);
  urlInput.addEventListener('change', syncAnalyzeButton);
  syncAnalyzeButton();
}

document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-form-accordion]').forEach(function (section) {
    var head = section.querySelector('[data-form-accordion-toggle]');
    var expandBtn = section.querySelector('.ds-accordion-expand');
    if (!head) return;
    if (section.hasAttribute('data-open-default')) {
      section.classList.add('is-open');
      if (expandBtn) expandBtn.setAttribute('aria-expanded', 'true');
    }
    head.addEventListener('click', function () {
      var open = !section.classList.contains('is-open');
      section.classList.toggle('is-open', open);
      if (expandBtn) expandBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  });
});
