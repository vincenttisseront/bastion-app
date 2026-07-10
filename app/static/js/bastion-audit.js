(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.severity-chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        var sev = chip.getAttribute('data-sev');
        var url = new URL(window.location.href);
        if (chip.classList.contains('active')) {
          url.searchParams.delete('severity');
        } else {
          url.searchParams.set('severity', sev);
        }
        window.location.href = url.toString();
      });
    });

    var form = document.getElementById('audit-filter-form');
    if (form) {
      form.addEventListener('change', function () {
        form.submit();
      });
    }
  });
})();
