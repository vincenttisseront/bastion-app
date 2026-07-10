(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.alert[data-dismiss]').forEach(function (el) {
      setTimeout(function () {
        el.style.opacity = '0';
        setTimeout(function () { el.remove(); }, 300);
      }, 5000);
    });

    document.querySelectorAll('[data-confirm]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        var msg = el.getAttribute('data-confirm') || 'Confirmer cette action ?';
        if (!window.confirm(msg)) {
          e.preventDefault();
          e.stopPropagation();
        }
      });
    });

    var searchInput = document.getElementById('sidebar-search');
    if (searchInput) {
      searchInput.addEventListener('input', function () {
        var q = searchInput.value.toLowerCase();
        document.querySelectorAll('.sidebar-nav-item').forEach(function (item) {
          var text = item.textContent.toLowerCase();
          item.style.display = text.indexOf(q) >= 0 ? '' : 'none';
        });
      });
    }
  });
})();
