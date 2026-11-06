/**
 * Loading indicator — one spinner for the whole UI (window.BastionBusy).
 *
 * Every indicator waits SHOW_DELAY_MS (300 ms) before it appears, so fast
 * responses never flash a spinner. Labels are read out through one shared
 * role="status" live region; the busy element also gets aria-busy="true".
 *
 * 1. Global overlay: automatic on form submits and mutating fetch calls.
 *      Opt-out:  <form data-bastion-busy="0">
 *                fetch(url, { bastionBusy: false })
 *                fetch(url, { headers: { "X-Bastion-Busy": "0" } })
 *      Label:    data-bastion-busy-label="…" on the form or its submit button.
 *      Scoped:   data-bastion-busy-target="#selector" on the form dims that
 *                region instead of covering the page (GET filter forms).
 *
 * 2. Around a promise (fetch that fills a panel, button action…):
 *      BastionBusy.during(promise, { target: el, label: "…" })  veil over a block
 *      BastionBusy.during(promise, { button: btn })             ring inside a button
 *      BastionBusy.during(promise, { inline: el })              ring + label added to el
 *      BastionBusy.during(promise)                              global overlay
 *    `promise` may be a function returning one. For flows that are not a single
 *    promise: var stop = BastionBusy.start({ ... }); …; stop();
 *
 * 3. Links that reload a slow page: <a data-bastion-busy-target="#sel"
 *    data-bastion-busy-label="…"> shows the veil on a plain left click. Scripts
 *    that navigate themselves call BastionBusy.navigating({ target, label }).
 *    When the region is off screen, the page overlay is used instead.
 *
 * 4. Downloads: <a data-bastion-download> or <form data-bastion-download> fetch
 *    the file with a ring in the trigger, then save it. A response that is not
 *    an attachment (error page) falls back to the native request; a redirect
 *    (flash message) reloads the page.
 */
(function () {
  "use strict";

  var SHOW_DELAY_MS = 300;
  var DEFAULT_LABEL = "Traitement en cours…";
  var LOADING_LABEL = "Chargement…";
  var DOWNLOAD_LABEL = "Préparation du téléchargement…";
  var NAV_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

  var QUIET_PATH_RE =
    /^\/api\/(admin\/notifications|search|sessions\/live-verify)\/?$/i;

  var nativeFetch =
    typeof window.fetch === "function" ? window.fetch.bind(window) : null;

  function t(msgid) {
    try {
      if (window.BastionI18n && typeof window.BastionI18n.t === "function") {
        return window.BastionI18n.t(msgid);
      }
    } catch (e) {}
    return msgid;
  }

  function resolveEl(ref) {
    if (!ref) return null;
    if (typeof ref === "string") {
      try {
        return document.querySelector(ref);
      } catch (e) {
        return null;
      }
    }
    return ref.nodeType === 1 ? ref : null;
  }

  function spinnerNode(size) {
    var el = document.createElement("span");
    el.className = "bastion-spinner" + (size ? " bastion-spinner--" + size : "");
    el.setAttribute("aria-hidden", "true");
    return el;
  }

  function loadingNode(label, size) {
    var wrap = document.createElement("span");
    wrap.className = "bastion-loading";
    wrap.appendChild(spinnerNode(size));
    var text = document.createElement("span");
    text.className = "bastion-loading-label";
    text.textContent = label;
    wrap.appendChild(text);
    return wrap;
  }

  /* ── Screen-reader announcements (one persistent live region) ── */

  var liveEl = null;
  var announced = [];

  function ensureLive() {
    if (liveEl) return liveEl;
    if (!document.body) return null;
    liveEl = document.createElement("div");
    liveEl.id = "bastion-busy-live";
    liveEl.className = "bastion-sr-only";
    liveEl.setAttribute("role", "status");
    liveEl.setAttribute("aria-live", "polite");
    document.body.appendChild(liveEl);
    return liveEl;
  }

  function announce(label, on) {
    var el = ensureLive();
    if (!el) return;
    if (on) {
      announced.push(label);
    } else {
      var i = announced.lastIndexOf(label);
      if (i >= 0) announced.splice(i, 1);
    }
    var text = announced.length ? announced[announced.length - 1] : "";
    if (el.textContent !== text) el.textContent = text;
  }

  /* ── Global overlay ── */

  var depth = 0;
  var showTimer = null;
  var overlay = null;
  var labelEl = null;
  var overlayLabel = "";

  function ensureOverlay() {
    if (overlay) return overlay;
    overlay = document.createElement("div");
    overlay.id = "bastion-busy-overlay";
    overlay.className = "bastion-busy-overlay";
    overlay.hidden = true;
    overlay.setAttribute("aria-hidden", "true");
    overlay.innerHTML =
      '<div class="bastion-busy-card">' +
      '<span class="bastion-spinner bastion-spinner--lg" aria-hidden="true"></span>' +
      '<span class="bastion-busy-label"></span>' +
      "</div>";
    labelEl = overlay.querySelector(".bastion-busy-label");
    (document.body || document.documentElement).appendChild(overlay);
    return overlay;
  }

  function paint(visible, label) {
    ensureOverlay();
    if (visible) {
      overlayLabel = label || t(DEFAULT_LABEL);
      if (labelEl) labelEl.textContent = overlayLabel;
      announce(overlayLabel, true);
    } else if (overlayLabel) {
      announce(overlayLabel, false);
      overlayLabel = "";
    }
    overlay.hidden = !visible;
    overlay.setAttribute("aria-hidden", visible ? "false" : "true");
    if (document.body) {
      document.body.classList.toggle("bastion-busy", visible);
    }
  }

  function show(label) {
    depth += 1;
    if (depth !== 1) return;
    var text = label || t(DEFAULT_LABEL);
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

  /* ── Scoped indicators (region veil, button, inline) ── */

  var scoped = new Map();

  function teardown(entry) {
    clearTimeout(entry.timer);
    entry.timer = null;
    scoped.delete(entry.host);
    if (entry.node && entry.node.parentNode) {
      entry.node.parentNode.removeChild(entry.node);
    }
    var host = entry.host;
    if (entry.kind === "button") host.classList.remove("is-busy");
    if (entry.kind === "target") {
      host.classList.remove("is-loading");
      if (entry.hosted) host.classList.remove("bastion-loading-host");
    }
    if (entry.prevBusy == null) host.removeAttribute("aria-busy");
    else host.setAttribute("aria-busy", entry.prevBusy);
    if (entry.disabled === "prop" && host.disabled) host.disabled = false;
    if (entry.disabled === "aria") {
      if (entry.prevAriaDisabled == null) host.removeAttribute("aria-disabled");
      else host.setAttribute("aria-disabled", entry.prevAriaDisabled);
    }
    if (entry.painted) announce(entry.label, false);
  }

  function paintScoped(entry) {
    entry.timer = null;
    entry.painted = true;
    var host = entry.host;
    if (entry.kind === "button") {
      host.classList.add("is-busy");
      entry.node = spinnerNode("sm");
      host.insertBefore(entry.node, host.firstChild);
    } else if (entry.kind === "target") {
      if (window.getComputedStyle(host).position === "static") {
        host.classList.add("bastion-loading-host");
        entry.hosted = true;
      }
      host.classList.add("is-loading");
      var veil = document.createElement("div");
      veil.className = "bastion-loading-veil";
      veil.appendChild(loadingNode(entry.label));
      host.appendChild(veil);
      entry.node = veil;
    } else {
      entry.node = loadingNode(entry.label, "sm");
      host.appendChild(entry.node);
    }
    announce(entry.label, true);
  }

  function releaser(entry) {
    var done = false;
    return function () {
      if (done) return;
      done = true;
      entry.count -= 1;
      if (entry.count <= 0 && scoped.get(entry.host) === entry) teardown(entry);
    };
  }

  /**
   * Start an indicator; returns a function that stops it (idempotent).
   * opts: { target | button | inline: Element or CSS selector, label, delay, disable }
   * Without an element, drives the global overlay.
   */
  function start(opts) {
    opts = opts || {};
    var button = resolveEl(opts.button);
    var target = button ? null : resolveEl(opts.target);
    var inlineEl = button || target ? null : resolveEl(opts.inline);
    var host = button || target || inlineEl;
    if (!host) {
      show(opts.label || undefined);
      var stopped = false;
      return function () {
        if (stopped) return;
        stopped = true;
        hide();
      };
    }
    var existing = scoped.get(host);
    if (existing) {
      existing.count += 1;
      return releaser(existing);
    }
    var kind = button ? "button" : target ? "target" : "inline";
    var entry = {
      host: host,
      kind: kind,
      count: 1,
      label: opts.label || t(kind === "button" ? DEFAULT_LABEL : LOADING_LABEL),
      node: null,
      painted: false,
      hosted: false,
      disabled: null,
      prevBusy: host.getAttribute("aria-busy"),
      prevAriaDisabled: null,
      timer: null,
    };
    host.setAttribute("aria-busy", "true");
    if (kind === "button" && opts.disable !== false) {
      if (host.tagName === "BUTTON" || host.tagName === "INPUT") {
        if (!host.disabled) {
          host.disabled = true;
          entry.disabled = "prop";
        }
      } else {
        entry.prevAriaDisabled = host.getAttribute("aria-disabled");
        host.setAttribute("aria-disabled", "true");
        entry.disabled = "aria";
      }
    }
    scoped.set(host, entry);
    var delay =
      typeof opts.delay === "number" && opts.delay >= 0 ? opts.delay : SHOW_DELAY_MS;
    entry.timer = setTimeout(function () {
      if (scoped.get(host) === entry) paintScoped(entry);
    }, delay);
    return releaser(entry);
  }

  /** Show an indicator while `work` (a promise, or a function returning one) runs. */
  function during(work, opts) {
    var release = start(opts);
    var promise;
    try {
      promise = typeof work === "function" ? work() : work;
    } catch (err) {
      release();
      return Promise.reject(err);
    }
    return Promise.resolve(promise).then(
      function (value) {
        release();
        return value;
      },
      function (err) {
        release();
        throw err;
      }
    );
  }

  /** Legacy helper: global overlay around a promise. */
  function wrap(promise, label) {
    return during(promise, { label: label });
  }

  function resetAll() {
    reset();
    Array.from(scoped.values()).forEach(teardown);
  }

  /* ── fetch(): global overlay on mutating calls ── */

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

  if (nativeFetch) {
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

  /* ── Downloads (fetch + save, spinner in the trigger) ── */

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function downloadName(disposition, url) {
    var star = /filename\*\s*=\s*[^']*'[^']*'([^;]+)/i.exec(disposition);
    if (star) {
      try {
        return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
      } catch (e) {}
    }
    var plain =
      /filename\s*=\s*"([^"]+)"/i.exec(disposition) ||
      /filename\s*=\s*([^;]+)/i.exec(disposition);
    if (plain) return plain[1].trim();
    try {
      var last = new URL(url, window.location.href).pathname.split("/").pop();
      if (last) return last;
    } catch (e) {}
    return "download";
  }

  function saveBlob(blob, name) {
    var href = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = href;
    a.download = name;
    a.rel = "noopener";
    a.hidden = true;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () {
      URL.revokeObjectURL(href);
    }, 60000);
  }

  function canDownload() {
    return !!(nativeFetch && window.URL && typeof URL.createObjectURL === "function");
  }

  function runDownload(req) {
    var release = start({
      button: req.trigger,
      label: req.label || t(DOWNLOAD_LABEL),
    });
    var headers = { Accept: NAV_ACCEPT };
    if (req.method !== "GET") {
      var tok = csrfToken();
      if (tok) headers["X-CSRF-Token"] = tok;
    }
    var init = {
      method: req.method,
      credentials: "same-origin",
      redirect: "manual",
      headers: headers,
    };
    if (req.body) init.body = req.body;
    return nativeFetch(req.url, init)
      .then(function (resp) {
        if (resp.type === "opaqueredirect") {
          // Server answered with a redirect (usually a flash message): show it.
          release();
          window.location.reload();
          return null;
        }
        var disposition = resp.headers.get("Content-Disposition") || "";
        if (!resp.ok || !/attachment/i.test(disposition)) {
          release();
          req.fallback();
          return null;
        }
        return resp.blob().then(function (blob) {
          saveBlob(blob, downloadName(disposition, req.url));
          release();
        });
      })
      .catch(function () {
        release();
        req.fallback();
      });
  }

  function formDataFor(form, submitter) {
    var fd;
    try {
      fd = submitter ? new FormData(form, submitter) : new FormData(form);
    } catch (e) {
      fd = new FormData(form);
      if (submitter && submitter.name) fd.append(submitter.name, submitter.value || "");
    }
    return fd;
  }

  function attrFrom(first, second, name) {
    var v = first && first.getAttribute ? first.getAttribute(name) : null;
    if (!v && second && second.getAttribute) v = second.getAttribute(name);
    return v || "";
  }

  function plainLeftClick(e) {
    return !(e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey);
  }

  function sameDocumentLink(a) {
    try {
      var url = new URL(a.href, window.location.href);
      return (
        url.origin === window.location.origin &&
        url.pathname === window.location.pathname &&
        url.search === window.location.search &&
        !!url.hash
      );
    } catch (e) {
      return false;
    }
  }

  function onDownloadSubmit(e) {
    var form = e.target;
    if (!form || form.tagName !== "FORM" || !form.hasAttribute("data-bastion-download")) return;
    if (e.defaultPrevented || !canDownload()) return;
    e.preventDefault();
    if (form.__bastionDownloading) return;
    var submitter = e.submitter || form.querySelector('[type="submit"]');
    var method = (form.getAttribute("method") || "GET").toUpperCase();
    var fd = formDataFor(form, submitter);
    var url = form.action;
    var body = null;
    if (method === "GET") {
      // Like a native GET submit: the form data replaces the action's query.
      var u = new URL(url, window.location.href);
      u.search = new URLSearchParams(fd).toString();
      url = u.toString();
    } else {
      body = /multipart/i.test(form.enctype || "") ? fd : new URLSearchParams(fd);
    }
    form.__bastionDownloading = true;
    runDownload({
      url: url,
      method: method,
      body: body,
      trigger: submitter,
      label: attrFrom(submitter, form, "data-bastion-busy-label"),
      fallback: function () {
        HTMLFormElement.prototype.submit.call(form);
      },
    }).then(function () {
      form.__bastionDownloading = false;
    });
  }

  function onDownloadClick(e) {
    if (!plainLeftClick(e) || !e.target || !e.target.closest) return;
    var a = e.target.closest("a[data-bastion-download]");
    if (!a || !canDownload()) return;
    e.preventDefault();
    if (a.__bastionDownloading) return;
    a.__bastionDownloading = true;
    var url = a.href;
    runDownload({
      url: url,
      method: "GET",
      trigger: a,
      label: a.getAttribute("data-bastion-busy-label") || "",
      fallback: function () {
        window.location.assign(url);
      },
    }).then(function () {
      a.__bastionDownloading = false;
    });
  }

  /* ── Forms and links that navigate ── */

  function inViewport(el) {
    try {
      var r = el.getBoundingClientRect();
      var vh = window.innerHeight || document.documentElement.clientHeight;
      return r.width > 0 && r.bottom > 0 && r.top < vh;
    } catch (e) {
      return true;
    }
  }

  /**
   * The page is about to load a new document: dim the region it will replace,
   * or cover the page when that region is out of sight (nothing would show).
   * opts: { target, label }. The indicator ends with the page (or on bfcache restore).
   */
  function navigating(opts) {
    opts = opts || {};
    var target = resolveEl(opts.target);
    var label = opts.label || "";
    if (target && inViewport(target)) start({ target: target, label: label || t(LOADING_LABEL) });
    else show(label || undefined);
  }

  function onSubmitCapture(e) {
    var form = e.target;
    if (!form || form.tagName !== "FORM") return;
    if (form.getAttribute("data-bastion-busy") === "0") return;
    if (form.hasAttribute("data-bastion-download")) return;
    // A form posting into another window never unloads this page.
    if (form.target && form.target !== "_self") return;
    var submitter = e.submitter || null;
    // Defer: AJAX handlers that preventDefault drive their own indicator.
    setTimeout(function () {
      if (e.defaultPrevented) return;
      navigating({
        target: form.getAttribute("data-bastion-busy-target"),
        label: attrFrom(submitter, form, "data-bastion-busy-label"),
      });
    }, 0);
  }

  function onNavClick(e) {
    if (!plainLeftClick(e) || !e.target || !e.target.closest) return;
    var a = e.target.closest("a[data-bastion-busy-target], a[data-bastion-busy-label]");
    if (!a || a.hasAttribute("data-bastion-download") || a.hasAttribute("download")) return;
    if (a.target && a.target !== "_self") return;
    if (a.getAttribute("aria-disabled") === "true" || sameDocumentLink(a)) return;
    navigating({
      target: a.getAttribute("data-bastion-busy-target"),
      label: a.getAttribute("data-bastion-busy-label") || "",
    });
  }

  window.BastionBusy = {
    SHOW_DELAY_MS: SHOW_DELAY_MS,
    show: show,
    hide: hide,
    reset: reset,
    resetAll: resetAll,
    wrap: wrap,
    start: start,
    during: during,
    navigating: navigating,
  };

  function onReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  onReady(function () {
    ensureOverlay();
    ensureLive();
    document.addEventListener("submit", onSubmitCapture, true);
    document.addEventListener("submit", onDownloadSubmit);
    document.addEventListener("click", onDownloadClick);
    document.addEventListener("click", onNavClick);
  });

  // Back/forward cache restores the page as it was when we left: drop stale spinners.
  window.addEventListener("pageshow", function (e) {
    if (e.persisted) resetAll();
  });
})();
