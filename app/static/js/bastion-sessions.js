(function () {
  'use strict';

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function postAction(url, confirmMsg) {
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCsrfToken(),
        'Content-Type': 'application/json',
      },
      credentials: 'same-origin',
    })
      .then(function (r) {
        if (!r.ok) throw new Error('Action failed');
        return r.json();
      })
      .then(function () {
        window.location.reload();
      })
      .catch(function () {
        alert('Erreur lors de l\'exécution de l\'action.');
      });
  }

  window.isolateSession = function (sessionId) {
    postAction('/admin/sessions/' + encodeURIComponent(sessionId) + '/isolate', 'Isoler cet hôte ?');
  };

  window.rotateKeys = function (sessionId) {
    postAction('/admin/sessions/' + encodeURIComponent(sessionId) + '/rotate-keys', 'Lancer la rotation des clés pour cette session ?');
  };

  // TODO(production): WebSocket/SSE for live session updates
  // var ws = new WebSocket('/api/sessions/ws');
})();
