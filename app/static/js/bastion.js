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
