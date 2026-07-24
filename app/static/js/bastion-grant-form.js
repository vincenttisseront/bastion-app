/**
 * RBAC "Ajouter un droit" — show exactly one resource field for the selected Type.
 * Clears previous resource values on Type change so hidden fields are never submitted.
 */
(function () {
  function wireGrantForm(typeSelect) {
    var form = typeSelect.closest("form");
    if (!form) return;

    var blocks = {
      application: form.querySelector("[data-grant-app]"),
      file: form.querySelector("[data-grant-file]"),
      folder: form.querySelector("[data-grant-folder]"),
      system_role: form.querySelector("[data-grant-role]"),
    };
    var fields = {
      application: form.querySelector('[data-grant-field="application_id"]'),
      file: form.querySelector('[data-grant-field="file_id"]'),
      folder: form.querySelector('[data-grant-field="folder_id"]'),
      system_role: form.querySelector('[data-grant-field="system_role"]'),
    };
    var fieldNames = {
      application: "application_id",
      file: "file_id",
      folder: "folder_id",
      system_role: "system_role",
    };

    function clearField(el) {
      if (!el) return;
      el.value = "";
      if (el.options && el.options.length) {
        el.selectedIndex = 0;
      }
    }

    function setActive(type) {
      Object.keys(blocks).forEach(function (key) {
        var block = blocks[key];
        var field = fields[key];
        var active = key === type;
        if (block) block.hidden = !active;
        if (!field) return;
        field.disabled = !active;
        if (active) {
          field.setAttribute("name", fieldNames[key]);
        } else {
          field.removeAttribute("name");
          clearField(field);
        }
      });
    }

    typeSelect.addEventListener("change", function () {
      setActive(typeSelect.value);
    });
    setActive(typeSelect.value);
  }

  document.querySelectorAll("[data-grant-resource-type]").forEach(wireGrantForm);
})();
