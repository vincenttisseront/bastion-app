/**
 * Global search modal — click #global-search-trigger → fetch /api/search.
 * Matching is server-side; this file only handles UI (render, highlight, a11y).
 */
(function (global) {
  "use strict";

  var MIN_LEN = 2;
  var DEBOUNCE_MS = 200;
  var DISPLAY_LIMIT = 5;

  var CATEGORY_URLS = {
    applications: "/apps",
    users: "/admin/rbac/users",
    groups: "/admin/rbac",
    sessions: "/sessions",
    realms: "/admin/realms",
    audit: "/audit",
  };

  var CATEGORY_ICONS = {
    applications:
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
    users:
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    groups:
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    sessions:
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
    realms:
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    audit:
      '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
  };

  var modal = null;
  var input = null;
  var resultsRoot = null;
  var previousFocus = null;
  var debounceTimer = null;
  var activeIndex = -1;
  var flatItems = [];
  var abortCtrl = null;
  var bound = false;
  var lastQuery = "";

  function $(sel, root) {
    return (root || document).querySelector(sel);
  }

  function $all(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  function debounce(fn, ms) {
    return function () {
      var args = arguments;
      var ctx = this;
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        fn.apply(ctx, args);
      }, ms);
    };
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function foldText(value) {
    try {
      return String(value || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase();
    } catch (_) {
      return String(value || "").toLowerCase();
    }
  }

  /** Highlight contiguous query match (accent/case insensitive). */
  function highlightHtml(text, query) {
    var raw = String(text == null ? "" : text);
    var q = foldText(query);
    if (!raw || !q) return escapeHtml(raw);

    var parts = [];
    for (var i = 0; i < raw.length; ) {
      var cp = raw.codePointAt(i);
      var ch = String.fromCodePoint(cp);
      var len = ch.length;
      var f = foldText(ch);
      if (f) parts.push({ f: f, start: i, end: i + len });
      i += len;
    }
    var folded = parts
      .map(function (p) {
        return p.f;
      })
      .join("");
    var idx = folded.indexOf(q);
    if (idx < 0) return escapeHtml(raw);

    var pos = 0;
    var origStart = -1;
    var origEnd = -1;
    for (var j = 0; j < parts.length; j++) {
      var piece = parts[j];
      var next = pos + piece.f.length;
      if (origStart < 0 && idx >= pos && idx < next) origStart = piece.start;
      if (origStart >= 0 && idx + q.length <= next) {
        origEnd = piece.end;
        break;
      }
      pos = next;
    }
    if (origStart < 0 || origEnd < 0) return escapeHtml(raw);

    return (
      escapeHtml(raw.slice(0, origStart)) +
      '<mark class="global-search-mark">' +
      escapeHtml(raw.slice(origStart, origEnd)) +
      "</mark>" +
      escapeHtml(raw.slice(origEnd))
    );
  }

  function setState(name) {
    $all("[data-global-search-state]", resultsRoot).forEach(function (el) {
      el.hidden = el.getAttribute("data-global-search-state") !== name;
    });
  }

  function updateEmptyTitle(q) {
    var el = $("[data-global-search-empty-title]", resultsRoot);
    if (!el) return;
    if (q) {
      el.textContent = 'Aucun résultat pour «\u00a0' + q + '\u00a0»';
    } else {
      el.textContent = "Aucun résultat";
    }
  }

  function close() {
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    modal.classList.remove("is-open");
    document.body.classList.remove("bastion-modal-open");
    if (debounceTimer) clearTimeout(debounceTimer);
    if (abortCtrl) {
      try {
        abortCtrl.abort();
      } catch (_) {}
      abortCtrl = null;
    }
    activeIndex = -1;
    flatItems = [];
    lastQuery = "";
    if (input) input.value = "";
    setState("idle");
    if (previousFocus && typeof previousFocus.focus === "function") {
      try {
        previousFocus.focus();
      } catch (_) {}
    }
    previousFocus = null;
  }

  function open() {
    if (!modal) return;
    previousFocus = document.activeElement;
    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    modal.classList.add("is-open");
    document.body.classList.add("bastion-modal-open");
    setState("idle");
    activeIndex = -1;
    flatItems = [];
    lastQuery = "";
    if (input) {
      input.value = "";
      setTimeout(function () {
        input.focus();
      }, 0);
    }
  }

  function highlight(index) {
    activeIndex = index;
    $all(".global-search-item", resultsRoot).forEach(function (el, i) {
      var on = i === index;
      el.classList.toggle("is-active", on);
      el.setAttribute("aria-selected", on ? "true" : "false");
      if (on) {
        try {
          el.scrollIntoView({ block: "nearest" });
        } catch (_) {}
      }
    });
  }

  function makeRow(item, categoryKey, query) {
    var a = document.createElement("a");
    a.href = item.url || "#";
    a.className = "global-search-item";
    a.setAttribute("role", "option");
    a.setAttribute("aria-selected", "false");

    var fullTitle = [item.label, item.sublabel].filter(Boolean).join(" — ");
    if (fullTitle) a.title = fullTitle;

    var icon = document.createElement("span");
    icon.className = "global-search-item-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML = CATEGORY_ICONS[categoryKey] || CATEGORY_ICONS.applications;

    var main = document.createElement("span");
    main.className = "global-search-item-main";

    var label = document.createElement("span");
    label.className = "global-search-item-label";
    label.innerHTML = highlightHtml(item.label || "", query);
    main.appendChild(label);

    a.appendChild(icon);
    a.appendChild(main);

    if (item.sublabel) {
      var badge = document.createElement("span");
      badge.className = "global-search-item-badge";
      badge.textContent = item.sublabel;
      badge.title = item.sublabel;
      a.appendChild(badge);
    }

    return a;
  }

  function renderResults(payload, query) {
    var results = (payload && payload.results) || {};
    var labels = (payload && payload.category_labels) || {};
    var keys = Object.keys(results);
    var container = $('[data-global-search-state="results"]', resultsRoot);
    if (!container) return;

    flatItems = [];
    container.innerHTML = "";
    var any = false;

    keys.forEach(function (key) {
      var items = results[key];
      if (!items || !items.length) return;
      any = true;

      var section = document.createElement("section");
      section.className = "global-search-section";

      var head = document.createElement("div");
      head.className = "global-search-section-head";
      var title = document.createElement("h3");
      title.className = "global-search-section-title";
      title.textContent = labels[key] || key;
      head.appendChild(title);
      section.appendChild(head);

      var list = document.createElement("ul");
      list.className = "global-search-list";

      var visible = items.slice(0, DISPLAY_LIMIT);
      visible.forEach(function (item) {
        var li = document.createElement("li");
        li.className = "global-search-list-item";
        var row = makeRow(item, key, query);
        var idx = flatItems.length;
        flatItems.push(row);
        row.addEventListener("mouseenter", function () {
          highlight(idx);
        });
        row.addEventListener("click", function () {
          close();
        });
        li.appendChild(row);
        list.appendChild(li);
      });
      section.appendChild(list);

      if (items.length > DISPLAY_LIMIT) {
        var more = document.createElement("a");
        more.className = "global-search-see-all";
        more.href = CATEGORY_URLS[key] || "#";
        more.textContent =
          "Voir tous les résultats (" + items.length + ")";
        more.addEventListener("click", function () {
          close();
        });
        section.appendChild(more);
      }

      container.appendChild(section);
    });

    if (!any) {
      updateEmptyTitle(query);
      setState("empty");
      return;
    }
    setState("results");
    highlight(0);
  }

  function runSearch() {
    if (!input) return;
    var q = (input.value || "").trim();
    lastQuery = q;
    if (q.length < MIN_LEN) {
      setState("idle");
      flatItems = [];
      activeIndex = -1;
      return;
    }
    setState("loading");
    if (abortCtrl) {
      try {
        abortCtrl.abort();
      } catch (_) {}
    }
    abortCtrl =
      typeof AbortController !== "undefined" ? new AbortController() : null;
    var opts = { headers: { Accept: "application/json" } };
    if (abortCtrl) opts.signal = abortCtrl.signal;
    fetch("/api/search?q=" + encodeURIComponent(q), opts)
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        if (!data || data.ok === false) {
          updateEmptyTitle(q);
          setState("empty");
          return;
        }
        renderResults(data, q);
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") return;
        updateEmptyTitle(q);
        setState("empty");
      });
  }

  var debouncedSearch = debounce(runSearch, DEBOUNCE_MS);

  function focusables() {
    if (!modal) return [];
    return $all(
      'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      modal
    ).filter(function (el) {
      return !el.hidden && el.offsetParent !== null;
    });
  }

  function onKeyDown(e) {
    if (!modal || modal.hidden) return;
    if (e.key === "Escape") {
      e.preventDefault();
      close();
      return;
    }
    if (e.key === "Tab") {
      var nodes = focusables();
      if (!nodes.length) return;
      var first = nodes[0];
      var last = nodes[nodes.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!flatItems.length) return;
      highlight(Math.min(flatItems.length - 1, activeIndex + 1));
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!flatItems.length) return;
      highlight(Math.max(0, activeIndex - 1));
      return;
    }
    if (e.key === "Enter") {
      if (activeIndex >= 0 && flatItems[activeIndex]) {
        e.preventDefault();
        flatItems[activeIndex].click();
      }
    }
  }

  function bindOnce() {
    if (bound) return;
    modal = $("#global-search-modal");
    input = $("#global-search-input");
    resultsRoot = $("#global-search-results");
    if (!modal || !input || !resultsRoot) return;
    bound = true;

    var trigger = $("#global-search-trigger");
    if (trigger) {
      trigger.addEventListener("click", function (e) {
        e.preventDefault();
        open();
      });
      trigger.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      });
    }

    $all("[data-global-search-dismiss]", modal).forEach(function (el) {
      el.addEventListener("click", function (e) {
        e.preventDefault();
        close();
      });
    });

    input.addEventListener("input", debouncedSearch);
    input.addEventListener("search", debouncedSearch);
    document.addEventListener("keydown", onKeyDown);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindOnce);
  } else {
    bindOnce();
  }

  global.BastionGlobalSearch = { open: open, close: close };
})(typeof window !== "undefined" ? window : this);
