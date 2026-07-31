/**
 * RBAC "Ajouter un droit" — contextual resource fields + modal open/submit.
 *
 * - Show exactly one resource field for the selected Type.
 * - Modal: [data-grant-modal-open] opens #grant-add-modal; AJAX submit keeps
 *   the modal open on error and reloads on success (with a brief flash).
 */
(function () {
  "use strict";

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
  }

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

  function showPageFlash(message, category) {
    try {
      sessionStorage.setItem(
        "bastion_page_flash",
        JSON.stringify({ message: message, category: category || "success" })
      );
    } catch (err) {
      /* ignore */
    }
  }

  function consumePageFlash() {
    var raw;
    try {
      raw = sessionStorage.getItem("bastion_page_flash");
      if (!raw) return;
      sessionStorage.removeItem("bastion_page_flash");
    } catch (err) {
      return;
    }
    var flash;
    try {
      flash = JSON.parse(raw);
    } catch (err) {
      return;
    }
    if (!flash || !flash.message) return;
    var container = document.querySelector(".flash-container");
    if (!container) {
      var main = document.getElementById("main-content");
      var body = document.querySelector(".app-body");
      container = document.createElement("div");
      container.className = "flash-container";
      if (main && main.parentNode) {
        main.parentNode.insertBefore(container, main);
      } else if (body) {
        body.insertBefore(container, body.firstChild);
      } else {
        return;
      }
    }
    var el = document.createElement("div");
    var cat = flash.category || "success";
    el.className = "alert alert-" + cat + " auto-close";
    el.setAttribute("role", "alert");
    el.textContent = flash.message;
    container.appendChild(el);
  }

  function wireGrantModal() {
    var modal = document.getElementById("grant-add-modal");
    var form = document.getElementById("grant-add-form");
    if (!modal || !form) return;

    var dialog = modal.querySelector(".bastion-modal-dialog");
    var errorEl = document.getElementById("grant-add-error");
    var submitBtn = document.getElementById("grant-add-submit");
    var previousFocus = null;

    function setError(msg) {
      if (!errorEl) return;
      if (msg) {
        errorEl.textContent = msg;
        errorEl.hidden = false;
      } else {
        errorEl.textContent = "";
        errorEl.hidden = true;
      }
    }

    function openModal() {
      previousFocus = document.activeElement;
      setError("");
      modal.hidden = false;
      modal.setAttribute("aria-hidden", "false");
      modal.classList.add("is-open");
      document.body.classList.add("bastion-modal-open");
      var typeSelect = form.querySelector("[data-grant-resource-type]");
      setTimeout(function () {
        if (typeSelect) typeSelect.focus();
        else if (dialog) dialog.focus();
      }, 0);
    }

    function closeModal() {
      modal.hidden = true;
      modal.setAttribute("aria-hidden", "true");
      modal.classList.remove("is-open");
      document.body.classList.remove("bastion-modal-open");
      setError("");
      if (previousFocus && typeof previousFocus.focus === "function") {
        try {
          previousFocus.focus();
        } catch (err) {
          /* ignore */
        }
      }
      previousFocus = null;
    }

    document.querySelectorAll("[data-grant-modal-open]").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        openModal();
      });
    });

    modal.addEventListener("click", function (e) {
      if (e.target.closest("[data-grant-modal-dismiss]")) {
        e.preventDefault();
        closeModal();
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !modal.hidden) {
        e.preventDefault();
        closeModal();
      }
    });

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      setError("");
      if (submitBtn) submitBtn.disabled = true;

      var headers = {
        Accept: "application/json",
        "Content-Type": "application/json",
      };
      var csrf = csrfToken();
      if (csrf) headers["X-CSRF-Token"] = csrf;

      var payload = {};
      var fd = new FormData(form);
      fd.forEach(function (value, key) {
        if (value === "" || value == null) return;
        payload[key] = value;
      });
      [
        "rbac_group_id",
        "application_id",
        "file_id",
        "folder_id",
        "rbac_role_id",
        "realm_id",
      ].forEach(function (k) {
        if (Object.prototype.hasOwnProperty.call(payload, k)) {
          var n = Number(payload[k]);
          if (!Number.isNaN(n)) payload[k] = n;
        }
      });

      fetch(form.getAttribute("action") || "/admin/rbac/grants", {
        method: "POST",
        body: JSON.stringify(payload),
        headers: headers,
        credentials: "same-origin",
      })
        .then(function (resp) {
          return resp.json().then(function (data) {
            return { ok: resp.ok, status: resp.status, data: data };
          }).catch(function () {
            return { ok: resp.ok, status: resp.status, data: null };
          });
        })
        .then(function (result) {
          if (submitBtn) submitBtn.disabled = false;
          if (result.ok && result.data && result.data.ok) {
            showPageFlash("Droit accordé.", "success");
            closeModal();
            location.reload();
            return;
          }
          var errors = (result.data && result.data.errors) || {};
          var msg =
            errors._form ||
            errors.__root__ ||
            Object.keys(errors)
              .map(function (k) {
                return errors[k];
              })
              .filter(Boolean)[0] ||
            (result.data && result.data.detail) ||
            "Impossible d’ajouter ce droit.";
          setError(typeof msg === "string" ? msg : String(msg));
        })
        .catch(function () {
          if (submitBtn) submitBtn.disabled = false;
          setError("Erreur réseau — réessayez.");
        });
    });
  }

  consumePageFlash();
  document.querySelectorAll("[data-grant-resource-type]").forEach(wireGrantForm);
  wireGrantModal();
})();
