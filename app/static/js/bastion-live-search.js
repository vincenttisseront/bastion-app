/**
 * Live / dynamic search: auto-submit GET filter forms and client-side table filters.
 *
 * - form[data-live-search]: debounce input on search/text fields; immediate submit on
 *   select/checkbox/radio change. Optional data-live-delay (ms, default 320).
 * - [data-live-filter]: client-side show/hide of rows matching data-live-filter-target
 *   (CSS selector). Rows match against textContent (case-insensitive, accent-folded lightly).
 */
(function () {
  "use strict";

  function debounce(fn, ms) {
    var t = null;
    return function () {
      var ctx = this;
      var args = arguments;
      if (t) clearTimeout(t);
      t = setTimeout(function () {
        fn.apply(ctx, args);
      }, ms);
    };
  }

  function submitForm(form) {
    if (!form) return;
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }

  function fold(s) {
    try {
      return String(s || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase();
    } catch (e) {
      return String(s || "").toLowerCase();
    }
  }

  function initLiveSearchForms() {
    document.querySelectorAll("form[data-live-search]").forEach(function (form) {
      if (form.dataset.liveSearchBound === "1") return;
      form.dataset.liveSearchBound = "1";
      var delay = parseInt(form.getAttribute("data-live-delay") || "320", 10);
      if (!isFinite(delay) || delay < 0) delay = 320;

      var submitDebounced = debounce(function () {
        submitForm(form);
      }, delay);

      form.addEventListener("input", function (ev) {
        var el = ev.target;
        if (!el || !el.matches) return;
        if (el.matches('input[type="search"], input[type="text"], input:not([type])')) {
          submitDebounced();
        }
      });

      form.addEventListener("change", function (ev) {
        var el = ev.target;
        if (!el || !el.matches) return;
        if (el.matches("select, input[type='checkbox'], input[type='radio']")) {
          submitForm(form);
        }
      });

      form.addEventListener("search", function (ev) {
        var el = ev.target;
        if (el && el.matches && el.matches('input[type="search"]')) {
          submitForm(form);
        }
      });
    });
  }

  function initLiveFilters() {
    document.querySelectorAll("[data-live-filter]").forEach(function (input) {
      if (input.dataset.liveFilterBound === "1") return;
      input.dataset.liveFilterBound = "1";
      var targetSel = input.getAttribute("data-live-filter");
      if (!targetSel) return;
      var delay = parseInt(input.getAttribute("data-live-delay") || "120", 10);
      if (!isFinite(delay) || delay < 0) delay = 120;

      var apply = debounce(function () {
        var q = fold(input.value || "").trim();
        document.querySelectorAll(targetSel).forEach(function (row) {
          var hay = fold(row.getAttribute("data-live-text") || row.textContent || "");
          var show = !q || hay.indexOf(q) !== -1;
          row.hidden = !show;
          row.style.display = show ? "" : "none";
        });
      }, delay);

      input.addEventListener("input", apply);
      input.addEventListener("search", apply);
      apply();
    });
  }

  function boot() {
    initLiveSearchForms();
    initLiveFilters();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.BastionLiveSearch = { init: boot };
})();
