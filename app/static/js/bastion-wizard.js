/**
 * BastionWizard — single-panel step wizard with horizontal stepper navigation.
 * Presentation only; forms/actions remain in the panel markup.
 *
 * Markup contract:
 *   [data-wizard] root with data-initial-step, optional data-complete="1"
 *   [data-wizard-goto="id"] step buttons (role=tab)
 *   [data-wizard-panel="id"] panels (role=tabpanel)
 *   [data-wizard-prev] / [data-wizard-next]
 *   optional [data-wizard-mode="review"|"edit"] inside a panel
 *   optional [data-wizard-edit] toggles review → edit within current panel
 */
(function (global) {
  "use strict";

  function init(root) {
    if (!root || root.getAttribute("data-wizard-ready") === "1") return null;
    root.setAttribute("data-wizard-ready", "1");

    var steps = Array.prototype.slice.call(
      root.querySelectorAll("[data-wizard-goto]")
    );
    var panels = Array.prototype.slice.call(
      root.querySelectorAll("[data-wizard-panel]")
    );
    if (!steps.length || !panels.length) return null;

    var order = steps.map(function (btn) {
      return btn.getAttribute("data-wizard-goto");
    });

    function isLocked(id) {
      var btn = root.querySelector('[data-wizard-goto="' + id + '"]');
      return !!(btn && btn.getAttribute("data-wizard-locked") === "1");
    }

    function isReachable(id) {
      var btn = root.querySelector('[data-wizard-goto="' + id + '"]');
      if (!btn) return false;
      if (btn.getAttribute("data-wizard-locked") === "1") return false;
      return true;
    }

    function showPanel(id, opts) {
      opts = opts || {};
      if (!isReachable(id) && !opts.force) return;

      panels.forEach(function (panel) {
        var on = panel.getAttribute("data-wizard-panel") === id;
        panel.hidden = !on;
        panel.setAttribute("aria-hidden", on ? "false" : "true");
      });

      steps.forEach(function (btn) {
        var sid = btn.getAttribute("data-wizard-goto");
        var on = sid === id;
        btn.classList.toggle("is-current", on);
        btn.setAttribute("aria-selected", on ? "true" : "false");
        btn.setAttribute("tabindex", on ? "0" : "-1");
      });

      root.setAttribute("data-wizard-active", id);

      var panel = root.querySelector('[data-wizard-panel="' + id + '"]');
      if (panel) {
        var preferEdit = opts.edit === true;
        var review = panel.querySelector('[data-wizard-mode="review"]');
        var edit = panel.querySelector('[data-wizard-mode="edit"]');
        if (review && edit) {
          var hasReview = review.getAttribute("data-wizard-has-review") === "1";
          if (preferEdit || !hasReview) {
            review.hidden = true;
            edit.hidden = false;
          } else {
            review.hidden = false;
            edit.hidden = true;
          }
        }
      }

      var idx = order.indexOf(id);
      var prevBtn = root.querySelector("[data-wizard-prev]");
      var nextBtn = root.querySelector("[data-wizard-next]");
      if (prevBtn) {
        var prevId = idx > 0 ? order[idx - 1] : null;
        prevBtn.disabled = !prevId || !isReachable(prevId);
      }
      if (nextBtn) {
        var nextId = idx >= 0 && idx < order.length - 1 ? order[idx + 1] : null;
        var canNext = nextId && isReachable(nextId);
        nextBtn.disabled = !canNext;
        nextBtn.hidden = idx === order.length - 1;
      }
    }

    function neighbor(delta) {
      var cur = root.getAttribute("data-wizard-active") || order[0];
      var idx = order.indexOf(cur);
      if (idx < 0) return;
      var target = order[idx + delta];
      while (target && !isReachable(target)) {
        idx += delta;
        target = order[idx];
      }
      if (target) showPanel(target);
    }

    steps.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-wizard-goto");
        if (isLocked(id)) return;
        showPanel(id);
      });
      btn.addEventListener("keydown", function (e) {
        if (e.key === "ArrowRight" || e.key === "ArrowDown") {
          e.preventDefault();
          neighbor(1);
        } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
          e.preventDefault();
          neighbor(-1);
        } else if (e.key === "Home") {
          e.preventDefault();
          var first = order.find(isReachable);
          if (first) showPanel(first);
        } else if (e.key === "End") {
          e.preventDefault();
          var last = null;
          order.forEach(function (id) {
            if (isReachable(id)) last = id;
          });
          if (last) showPanel(last);
        }
      });
    });

    var prev = root.querySelector("[data-wizard-prev]");
    var next = root.querySelector("[data-wizard-next]");
    if (prev) prev.addEventListener("click", function () { neighbor(-1); });
    if (next) next.addEventListener("click", function () { neighbor(1); });

    root.querySelectorAll("[data-wizard-edit]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var panel = btn.closest("[data-wizard-panel]");
        if (!panel) return;
        showPanel(panel.getAttribute("data-wizard-panel"), { edit: true, force: true });
      });
    });

    root.querySelectorAll("[data-wizard-cancel-edit]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var panel = btn.closest("[data-wizard-panel]");
        if (!panel) return;
        showPanel(panel.getAttribute("data-wizard-panel"), { edit: false, force: true });
      });
    });

    var initial =
      root.getAttribute("data-initial-step") ||
      order.find(function (id) {
        var btn = root.querySelector('[data-wizard-goto="' + id + '"]');
        return btn && btn.getAttribute("data-wizard-status") === "todo";
      }) ||
      order[0];
    if (!isReachable(initial)) {
      initial = order.find(isReachable) || order[0];
    }
    showPanel(initial, { force: true });

    return { show: showPanel, next: function () { neighbor(1); }, prev: function () { neighbor(-1); } };
  }

  function autoInit() {
    document.querySelectorAll("[data-wizard]").forEach(init);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", autoInit);
  } else {
    autoInit();
  }

  global.BastionWizard = { init: init, autoInit: autoInit };
})(typeof window !== "undefined" ? window : this);
