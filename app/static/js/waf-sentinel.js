/**
 * WAF Sentinel dashboard — inspect payload modal.
 */
(function () {
  'use strict';

  var dialog = document.getElementById('waf-inspect-dialog');
  var pre = document.getElementById('waf-inspect-pre');
  var titleEl = document.getElementById('waf-inspect-title');
  if (!dialog || !pre) return;

  function decodePayload(b64) {
    try {
      var binary = atob(b64);
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      var json = new TextDecoder('utf-8').decode(bytes);
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

  document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('[data-waf-inspect]') : null;
    if (!btn) return;
    e.preventDefault();
    var b64 = btn.getAttribute('data-waf-inspect') || '';
    var ip = btn.getAttribute('data-waf-inspect-ip') || '';
    if (titleEl) titleEl.textContent = ip ? 'Inspection · ' + ip : 'Détail événement';
    var obj = decodePayload(b64);
    pre.textContent = formatInspectBody(obj);
    if (typeof dialog.showModal === 'function') dialog.showModal();
  });

  var closeBtn = document.getElementById('waf-inspect-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function () {
      dialog.close();
    });
  }
})();
