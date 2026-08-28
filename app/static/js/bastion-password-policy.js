/**
 * Live password complexity checklist (profile self-service).
 */
(function (global) {
  'use strict';

  var RULES = [
    { id: 'length', test: function (p) { return p.length >= 12; } },
    { id: 'uppercase', test: function (p) { return /[A-Z]/.test(p); } },
    { id: 'lowercase', test: function (p) { return /[a-z]/.test(p); } },
    { id: 'digit', test: function (p) { return /\d/.test(p); } },
    { id: 'punctuation', test: function (p) { return /[^\w\s]/.test(p); } }
  ];

  function evaluate(password) {
    var out = {};
    RULES.forEach(function (rule) {
      out[rule.id] = rule.test(password || '');
    });
    return out;
  }

  function allMet(checks) {
    return RULES.every(function (rule) { return checks[rule.id]; });
  }

  function paint(checklist, checks) {
    if (!checklist) return;
    checklist.querySelectorAll('[data-rule]').forEach(function (item) {
      var id = item.getAttribute('data-rule');
      item.classList.toggle('is-met', Boolean(checks[id]));
    });
  }

  function bind(inputSelector, checklistSelector, options) {
    var input = document.querySelector(inputSelector);
    var checklist = document.querySelector(checklistSelector);
    if (!input || !checklist) return;

    var submitButton = options && options.submitButton
      ? document.querySelector(options.submitButton)
      : null;

    function sync() {
      var checks = evaluate(input.value);
      paint(checklist, checks);
      if (submitButton) {
        submitButton.disabled = !allMet(checks);
      }
    }

    input.addEventListener('input', sync);
    input.addEventListener('change', sync);
    sync();
  }

  global.BastionPasswordPolicy = {
    evaluate: evaluate,
    allMet: allMet,
    bind: bind
  };
})(window);
