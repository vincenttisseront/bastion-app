/**
 * BastionFuzzy — client-side fuzzy filter (Fuse.js), show/hide only (no DOM reorder).
 * Requires window.Fuse from /static/js/vendor/fuse.min.js
 */
(function (global) {
  "use strict";

  var instances = Object.create(null);

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

  function applyInstance(inst) {
    var q = (inst.input.value || "").trim();
    var matched = null;
    if (q.length > 0 && inst.fuse) {
      matched = Object.create(null);
      inst.fuse.search(q).forEach(function (r) {
        matched[r.item._id] = true;
      });
    }
    inst.records.forEach(function (rec) {
      var textOk = matched === null || matched[rec._id] === true;
      var extraOk = !inst.extraMatch || inst.extraMatch(rec.el) !== false;
      var show = textOk && extraOk;
      rec.el.style.display = show ? "" : "none";
      rec.el.hidden = !show;
    });
    if (typeof inst.onNoResults === "function") {
      var anyVisible = inst.records.some(function (rec) {
        return rec.el.style.display !== "none" && !rec.el.hidden;
      });
      inst.onNoResults(inst.container, !anyVisible && q.length > 0);
    }
  }

  function init(config) {
    if (!config || !config.inputId || !config.itemSelector) return null;
    var input = document.getElementById(config.inputId);
    if (!input) return null;
    if (typeof global.Fuse !== "function") {
      if (typeof console !== "undefined" && console.warn) {
        console.warn("BastionFuzzy: Fuse.js not loaded");
      }
      return null;
    }

    var nodes = Array.prototype.slice.call(
      document.querySelectorAll(config.itemSelector)
    );
    if (!nodes.length) return null;

    var getKey =
      typeof config.getKey === "function"
        ? config.getKey
        : function (el) {
            return (el.dataset && el.dataset.fuzzyKey) || el.textContent || "";
          };

    var records = nodes.map(function (el, i) {
      return {
        _id: String(i),
        el: el,
        key: String(getKey(el) || "").trim(),
      };
    });

    var threshold =
      typeof config.threshold === "number" ? config.threshold : 0.35;
    var debounceMs =
      typeof config.debounceMs === "number" ? config.debounceMs : 130;

    var fuse = new global.Fuse(records, {
      includeScore: true,
      threshold: threshold,
      ignoreLocation: true,
      keys: ["key"],
    });

    var container =
      (config.containerSelector &&
        document.querySelector(config.containerSelector)) ||
      (nodes[0] && nodes[0].parentElement) ||
      null;

    var inst = {
      input: input,
      fuse: fuse,
      records: records,
      extraMatch: config.extraMatch || null,
      onNoResults: config.onNoResults || null,
      container: container,
      apply: function () {
        applyInstance(inst);
      },
    };

    instances[config.inputId] = inst;

    var onInput = debounce(function () {
      applyInstance(inst);
    }, debounceMs);

    input.addEventListener("input", onInput);
    input.addEventListener("search", onInput);

    return inst;
  }

  function reapply(inputId) {
    var inst = instances[inputId];
    if (inst) applyInstance(inst);
  }

  function reapplyAll() {
    Object.keys(instances).forEach(function (id) {
      applyInstance(instances[id]);
    });
  }

  global.BastionFuzzy = {
    init: init,
    reapply: reapply,
    reapplyAll: reapplyAll,
  };
})(typeof window !== "undefined" ? window : this);
