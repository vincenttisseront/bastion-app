/**
 * WAF Sentinel dashboard — inspect payload + OWASP rule drill-down.
 */
(function () {
  'use strict';

  var dialog = document.getElementById('waf-inspect-dialog');
  var pre = document.getElementById('waf-inspect-pre');
  var titleEl = document.getElementById('waf-inspect-title');
  var ruleDialog = document.getElementById('waf-rule-logs-dialog');
  var ruleTitle = document.getElementById('waf-rule-logs-title');
  var ruleHint = document.getElementById('waf-rule-logs-hint');
  var ruleBody = document.getElementById('waf-rule-logs-body');
  var feedFilterHint = null;

  function b64ToBytes(b64) {
    var binary = atob(b64);
    return Uint8Array.from(binary, function (ch) {
      return ch.charCodeAt(0);
    });
  }

  function decodePayload(b64) {
    try {
      var json = new TextDecoder('utf-8').decode(b64ToBytes(b64));
      return JSON.parse(json);
    } catch (e) {
      return null;
    }
  }

  function formatInspectBody(obj) {
    if (!obj || typeof obj !== 'object') {
      return 'Payload illisible.';
    }
    var lines = [];
    var chain = obj.rule_chain_display;
    if (!chain && Array.isArray(obj.rule_chain) && obj.rule_chain.length) {
      chain = obj.rule_chain
        .map(function (item) {
          if (!item || !item.rule_id) return '';
          return item.rule_id + ' (' + (item.label || 'Règle CRS ' + item.rule_id) + ')';
        })
        .filter(Boolean)
        .join(' → ');
    }
    if (chain) {
      lines.push('Règles déclenchées : ' + chain);
      lines.push('');
    }
    if (Array.isArray(obj.all_rule_ids) && obj.all_rule_ids.length > 1) {
      lines.push('IDs CRS (' + obj.all_rule_ids.length + ') : ' + obj.all_rule_ids.join(', '));
      lines.push('');
    }
    lines.push(JSON.stringify(obj, null, 2));
    return lines.join('\n');
  }

  function parseEventsB64(b64) {
    if (!b64) return [];
    try {
      var json = new TextDecoder('utf-8').decode(b64ToBytes(b64));
      var parsed = JSON.parse(json);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  function ensureFeedFilterHint() {
    if (feedFilterHint) return feedFilterHint;
    var wrap = document.querySelector('#waf-page .sentinel-feed-wrap');
    if (!wrap || !wrap.parentElement) return null;
    feedFilterHint = document.createElement('p');
    feedFilterHint.className = 'sentinel-feed-filter-hint';
    feedFilterHint.hidden = true;
    wrap.parentElement.insertBefore(feedFilterHint, wrap);
    return feedFilterHint;
  }

  function filterFeedByRule(ruleId, label) {
    var rows = document.querySelectorAll('#waf-page .sentinel-feed-row');
    var visible = 0;
    rows.forEach(function (row) {
      var ids = (row.getAttribute('data-feed-rule-ids') || row.getAttribute('data-feed-rule-id') || '')
        .split(',')
        .map(function (s) { return s.trim(); })
        .filter(Boolean);
      var match = !ruleId || ids.indexOf(ruleId) !== -1;
      row.hidden = !match;
      if (match) visible += 1;
    });
    var hint = ensureFeedFilterHint();
    if (!hint) return;
    if (!ruleId) {
      hint.hidden = true;
      hint.textContent = '';
      return;
    }
    hint.hidden = false;
    hint.textContent = '';
    hint.appendChild(document.createTextNode('Filtre actif : règle '));
    var strong = document.createElement('strong');
    strong.textContent = String(ruleId || '');
    hint.appendChild(strong);
    if (label) {
      hint.appendChild(document.createTextNode(' — ' + String(label)));
    }
    hint.appendChild(document.createTextNode(' · ' + visible + ' ligne(s) · '));
    var clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'btn btn-ghost btn-sm';
    clearBtn.setAttribute('data-waf-clear-rule-filter', '');
    clearBtn.textContent = 'Tout afficher';
    hint.appendChild(clearBtn);
  }

  function appendTd(tr, text, className, title) {
    var td = document.createElement('td');
    if (className) td.className = className;
    if (title) td.title = title;
    td.textContent = text == null ? '—' : String(text);
    tr.appendChild(td);
    return td;
  }

  function openRuleLogs(ruleId, label, count, events) {
    if (!ruleDialog || !ruleBody) return;
    if (ruleTitle) {
      ruleTitle.textContent = 'Logs · ' + ruleId + (label ? ' — ' + label : '');
    }
    if (ruleHint) {
      ruleHint.textContent =
        count + ' déclenchement(s) / 24 h · ' +
        events.length + ' événement(s) récents disponibles dans le feed agrégé.';
    }
    ruleBody.textContent = '';
    if (!events.length) {
      var emptyTr = document.createElement('tr');
      var emptyTd = document.createElement('td');
      emptyTd.colSpan = 5;
      emptyTd.className = 'muted';
      emptyTd.style.padding = '1rem';
      emptyTd.textContent =
        'Aucun événement récent encore indexé pour cette règle. ' +
        'Le compteur 24 h reste valide ; de nouveaux logs apparaîtront ici après agrégation.';
      emptyTr.appendChild(emptyTd);
      ruleBody.appendChild(emptyTr);
    } else {
      events.forEach(function (ev) {
        var tr = document.createElement('tr');
        var target = (ev.host || '—') + (ev.uri || '');
        appendTd(tr, ev.timestamp || '—', 'sentinel-mono');
        appendTd(tr, ev.client_ip || '—', 'sentinel-mono');
        appendTd(tr, target, 'sentinel-mono', target);
        appendTd(
          tr,
          ev.blocked ? 'Bloqué' : 'Alerté',
          ev.blocked ? 'sentinel-action-ok' : 'sentinel-action-warn'
        );
        appendTd(tr, ev.message || '—', null, ev.message || '');
        ruleBody.appendChild(tr);
      });
    }
    filterFeedByRule(ruleId, label);
    var feed = document.querySelector('#waf-page .sentinel-feed-wrap');
    if (feed) feed.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (typeof ruleDialog.showModal === 'function') ruleDialog.showModal();
  }

  document.addEventListener('click', function (e) {
    var clearBtn = e.target && e.target.closest ? e.target.closest('[data-waf-clear-rule-filter]') : null;
    if (clearBtn) {
      e.preventDefault();
      filterFeedByRule('', '');
      document.querySelectorAll('.sentinel-owasp-row.is-active').forEach(function (el) {
        el.classList.remove('is-active');
      });
      return;
    }

    var ruleBtn = e.target && e.target.closest ? e.target.closest('[data-waf-rule-id]') : null;
    if (ruleBtn) {
      e.preventDefault();
      document.querySelectorAll('.sentinel-owasp-row.is-active').forEach(function (el) {
        el.classList.remove('is-active');
      });
      ruleBtn.classList.add('is-active');
      openRuleLogs(
        ruleBtn.getAttribute('data-waf-rule-id') || '',
        ruleBtn.getAttribute('data-waf-rule-label') || '',
        ruleBtn.getAttribute('data-waf-rule-count') || '0',
        parseEventsB64(ruleBtn.getAttribute('data-waf-rule-events-b64') || '')
      );
      return;
    }

    var btn = e.target && e.target.closest ? e.target.closest('[data-waf-inspect]') : null;
    if (!btn || !dialog || !pre) return;
    e.preventDefault();
    var b64 = btn.getAttribute('data-waf-inspect') || '';
    var ip = btn.getAttribute('data-waf-inspect-ip') || '';
    if (titleEl) titleEl.textContent = ip ? 'Inspection · ' + ip : 'Détail événement';
    var obj = decodePayload(b64);
    pre.textContent = formatInspectBody(obj);
    if (typeof dialog.showModal === 'function') dialog.showModal();
  });

  var closeBtn = document.getElementById('waf-inspect-close');
  if (closeBtn && dialog) {
    closeBtn.addEventListener('click', function () {
      dialog.close();
    });
  }
  var ruleClose = document.getElementById('waf-rule-logs-close');
  if (ruleClose && ruleDialog) {
    ruleClose.addEventListener('click', function () {
      ruleDialog.close();
    });
  }
})();
