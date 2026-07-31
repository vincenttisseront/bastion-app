/**
 * Global busy overlay — spinner during form submits and mutating fetch calls.
 *
 * Opt-out:
 *   <form data-bastion-busy="0">
 *   fetch(url, { bastionBusy: false })
 *   fetch(url, { headers: { "X-Bastion-Busy": "0" } })
 */
(function () {
  "use strict";

  var depth = 0;
  var showTimer = null;
  var overlay = null;
  var labelEl = null;
  var SHOW_DELAY_MS = 120;
  var DEFAULT_LABEL = "Traitement en cours…";

  var QUIET_PATH_RE =
    /^\/api\/(admin\/notifications|search|sessions\/live-verify)\/?$/i;

  function ensureOverlay() {
    if (overlay) return overlay;
    overlay = document.createElement("div");
    overlay.id = "bastion-busy-overlay";
    overlay.className = "bastion-busy-overlay";
    overlay.hidden = true;
    overlay.setAttribute("role", "status");
    overlay.setAttribute("aria-live", "polite");
    overlay.setAttribute("aria-busy", "true");
    overlay.innerHTML =
      '<div class="bastion-busy-card">' +
      '<span class="bastion-busy-spinner" aria-hidden="true"></span>' +
      '<span class="bastion-busy-label"></span>' +
      "</div>";
    labelEl = overlay.querySelector(".bastion-busy-label");
    if (labelEl) labelEl.textContent = DEFAULT_LABEL;
    (document.body || document.documentElement).appendChild(overlay);
    return overlay;
  }

  function paint(visible, label) {
    ensureOverlay();
    if (labelEl) labelEl.textContent = label || DEFAULT_LABEL;
    overlay.hidden = !visible;
    overlay.setAttribute("aria-hidden", visible ? "false" : "true");
    if (document.body) {
      document.body.classList.toggle("bastion-busy", visible);
    }
  }

  function show(label) {
    depth += 1;
    if (depth !== 1) return;
    var text = label || DEFAULT_LABEL;
    clearTimeout(showTimer);
    showTimer = setTimeout(function () {
      showTimer = null;
      if (depth > 0) paint(true, text);
    }, SHOW_DELAY_MS);
  }

  function hide() {
    if (depth <= 0) {
      depth = 0;
      return;
    }
    depth -= 1;
    if (depth > 0) return;
    clearTimeout(showTimer);
    showTimer = null;
    paint(false);
  }

  function reset() {
    depth = 0;
    clearTimeout(showTimer);
    showTimer = null;
    paint(false);
  }

  function wrap(promise, label) {
    show(label);
    return Promise.resolve(promise).then(
      function (value) {
        hide();
        return value;
      },
      function (err) {
        hide();
        throw err;
      }
    );
  }

  function requestUrl(input) {
    try {
      if (typeof input === "string") return input;
      if (input && typeof input.url === "string") return input.url;
    } catch (e) {}
    return "";
  }

  function requestMethod(input, init) {
    var method = (init && init.method) || "GET";
    try {
      if ((!init || !init.method) && input && typeof input.method === "string") {
        method = input.method;
      }
    } catch (e) {}
    return String(method || "GET").toUpperCase();
  }

  function headerBusyFlag(init) {
    if (!init || !init.headers) return null;
    var headers = init.headers;
    try {
      if (typeof headers.get === "function") {
        var v = headers.get("X-Bastion-Busy");
        if (v != null) return String(v);
      } else if (Array.isArray(headers)) {
        for (var i = 0; i < headers.length; i++) {
          if (String(headers[i][0]).toLowerCase() === "x-bastion-busy") {
            return String(headers[i][1]);
          }
        }
      } else if (typeof headers === "object") {
        for (var key in headers) {
          if (
            Object.prototype.hasOwnProperty.call(headers, key) &&
            key.toLowerCase() === "x-bastion-busy"
          ) {
            return String(headers[key]);
          }
        }
      }
    } catch (e) {}
    return null;
  }

  function shouldBusy(input, init) {
    init = init || {};
    if (init.bastionBusy === false || init.bastionBusy === 0) return false;
    if (init.bastionBusy === true || init.bastionBusy === 1) return true;
    var flag = headerBusyFlag(init);
    if (flag === "0" || flag === "false") return false;
    if (flag === "1" || flag === "true") return true;
    var url = requestUrl(input);
    try {
      var pathname = new URL(url, window.location.origin).pathname;
      if (QUIET_PATH_RE.test(pathname)) return false;
    } catch (e) {
      if (QUIET_PATH_RE.test(url)) return false;
    }
    var method = requestMethod(input, init);
    return method !== "GET" && method !== "HEAD";
  }

  function stripBusyOption(init) {
    if (!init || typeof init !== "object") return init;
    if (!Object.prototype.hasOwnProperty.call(init, "bastionBusy")) return init;
    var copy = {};
    for (var k in init) {
      if (Object.prototype.hasOwnProperty.call(init, k) && k !== "bastionBusy") {
        copy[k] = init[k];
      }
    }
    return copy;
  }

  window.BastionBusy = {
    show: show,
    hide: hide,
    reset: reset,
    wrap: wrap,
  };

  if (typeof window.fetch === "function") {
    var nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      var busy = shouldBusy(input, init || {});
      var opts = stripBusyOption(init);
      if (!busy) return nativeFetch(input, opts);
      show();
      return nativeFetch(input, opts).then(
        function (resp) {
          hide();
          return resp;
        },
        function (err) {
          hide();
          throw err;
        }
      );
    };
  }

  function onReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  onReady(function () {
    ensureOverlay();
    document.addEventListener(
      "submit",
      function (e) {
        var form = e.target;
        if (!form || form.tagName !== "FORM") return;
        if (form.getAttribute("data-bastion-busy") === "0") return;
        // Defer: AJAX handlers that preventDefault will drive busy via fetch.
        setTimeout(function () {
          if (e.defaultPrevented) return;
          show();
        }, 0);
      },
      true
    );
  });
})();
