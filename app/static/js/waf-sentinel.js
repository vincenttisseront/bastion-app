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
      return JSON.stringify(JSON.parse(json), null, 2);
    } catch (e) {
      return 'Payload illisible.';
    }
  }

  document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('[data-waf-inspect]') : null;
    if (!btn) return;
    e.preventDefault();
    var b64 = btn.getAttribute('data-waf-inspect') || '';
    var ip = btn.getAttribute('data-waf-inspect-ip') || '';
    if (titleEl) titleEl.textContent = ip ? 'Inspection · ' + ip : 'Détail événement';
    pre.textContent = decodePayload(b64);
    if (typeof dialog.showModal === 'function') dialog.showModal();
  });

  var closeBtn = document.getElementById('waf-inspect-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', function () {
      dialog.close();
    });
  }
})();
