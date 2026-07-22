/**
 * Global search modal — click #global-search-trigger → fetch /api/search.
 * Matching is server-side; categories not authorized for the user are absent from JSON.
 */
(function (global) {
  "use strict";

  var MIN_LEN = 2;
  var DEBOUNCE_MS = 200;
  var modal = null;
  var input = null;
  var resultsRoot = null;
  var previousFocus = null;
  var debounceTimer = null;
  var activeIndex = -1;
  var flatItems = [];
  var abortCtrl = null;
  var bound = false;

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

  function setState(name) {
    $all("[data-global-search-state]", resultsRoot).forEach(function (el) {
      el.hidden = el.getAttribute("data-global-search-state") !== name;
    });
  }

  function close() {
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    modal.classList.remove("is-open");
    document.body.classList.remove("bastion-modal-open");
    if (debounceTimer) clearTimeout(debounceTimer);
    if (abortCtrl) {
      try { abortCtrl.abort(); } catch (_) {}
      abortCtrl = null;
    }
    activeIndex = -1;
    flatItems = [];
    if (input) input.value = "";
    setState("idle");
    if (previousFocus && typeof previousFocus.focus === "function") {
      try { previousFocus.focus(); } catch (_) {}
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
    if (input) {
      input.value = "";
      setTimeout(function () { input.focus(); }, 0);
    }
  }

  function highlight(index) {
    activeIndex = index;
    $all(".global-search-item", resultsRoot).forEach(function (el, i) {
      var on = i === index;
      el.classList.toggle("is-active", on);
      el.setAttribute("aria-selected", on ? "true" : "false");
      if (on) {
        try { el.scrollIntoView({ block: "nearest" }); } catch (_) {}
      }
    });
  }

  function renderResults(payload) {
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
      var title = document.createElement("h3");
      title.className = "global-search-section-title";
      title.textContent = labels[key] || key;
      section.appendChild(title);
      var list = document.createElement("ul");
      list.className = "global-search-list";
      items.forEach(function (item) {
        var li = document.createElement("li");
        var btn = document.createElement("a");
        btn.href = item.url || "#";
        btn.className = "global-search-item";
        btn.setAttribute("role", "option");
        btn.setAttribute("aria-selected", "false");
        var label = document.createElement("span");
        label.className = "global-search-item-label";
        label.textContent = item.label || "";
        btn.appendChild(label);
        if (item.sublabel) {
          var sub = document.createElement("span");
          sub.className = "global-search-item-sub";
          sub.textContent = item.sublabel;
          btn.appendChild(sub);
        }
        var idx = flatItems.length;
        flatItems.push(btn);
        btn.addEventListener("mouseenter", function () { highlight(idx); });
        btn.addEventListener("click", function () {
          close();
        });
        li.appendChild(btn);
        list.appendChild(li);
      });
      section.appendChild(list);
      container.appendChild(section);
    });

    if (!any) {
      setState("empty");
      return;
    }
    setState("results");
    highlight(0);
  }

  function runSearch() {
    if (!input) return;
    var q = (input.value || "").trim();
    if (q.length < MIN_LEN) {
      setState("idle");
      flatItems = [];
      activeIndex = -1;
      return;
    }
    setState("loading");
    if (abortCtrl) {
      try { abortCtrl.abort(); } catch (_) {}
    }
    abortCtrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    var opts = { headers: { Accept: "application/json" } };
    if (abortCtrl) opts.signal = abortCtrl.signal;
    fetch("/api/search?q=" + encodeURIComponent(q), opts)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data || data.ok === false) {
          setState("empty");
          return;
        }
        renderResults(data);
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") return;
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
      // Open on click only (no Ctrl/Cmd+K). Enter/Space still activate the control.
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
