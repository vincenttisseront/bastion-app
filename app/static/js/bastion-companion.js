/**
 * Companion IA widget — logged-in users only (the markup is not rendered otherwise).
 * Everything the server or the user writes is inserted with textContent: no HTML,
 * no Markdown, no inline handlers (edge CSP is script-src 'self'). The conversation
 * lives in memory only (nothing in localStorage); history sent is capped.
 */
(function () {
  "use strict";

  var root = document.getElementById("companion");
  if (!root) return;

  var endpoint = root.getAttribute("data-endpoint") || "/api/companion/messages";
  var maxChars = parseInt(root.getAttribute("data-max-chars") || "600", 10);
  var MAX_HISTORY = 6;

  var toggle = root.querySelector("[data-companion-toggle]");
  var panel = root.querySelector("[data-companion-panel]");
  var closeBtn = root.querySelector("[data-companion-close]");
  var log = root.querySelector("[data-companion-log]");
  var chips = root.querySelector("[data-companion-chips]");
  var form = root.querySelector("[data-companion-form]");
  var input = root.querySelector("[data-companion-input]");
  var sendBtn = root.querySelector("[data-companion-send]");

  var history = [];
  var busy = false;

  function attr(name) {
    return root.getAttribute(name) || "";
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function isSafePath(url) {
    return typeof url === "string" && url.charAt(0) === "/" && url.charAt(1) !== "/" && url.indexOf("\\") === -1;
  }

  function open() {
    panel.hidden = false;
    toggle.setAttribute("aria-expanded", "true");
    input.focus();
  }

  function close() {
    panel.hidden = true;
    toggle.setAttribute("aria-expanded", "false");
    toggle.focus();
  }

  function scrollDown() {
    log.scrollTop = log.scrollHeight;
  }

  function addMessage(role, text, extraClass) {
    var el = document.createElement("div");
    el.className = "companion-msg companion-msg--" + role + (extraClass ? " " + extraClass : "");
    el.textContent = text;
    log.appendChild(el);
    scrollDown();
    return el;
  }

  function addNotices(notices) {
    (notices || []).forEach(function (text) {
      var el = document.createElement("div");
      el.className = "companion-notice";
      el.setAttribute("role", "alert");
      el.textContent = String(text);
      log.appendChild(el);
    });
  }

  function addLinks(links) {
    var safe = (links || []).filter(function (l) {
      return l && isSafePath(l.url) && l.label;
    });
    if (!safe.length) return;
    var wrap = document.createElement("div");
    wrap.className = "companion-links";
    safe.forEach(function (l) {
      var a = document.createElement("a");
      a.href = l.url;
      a.textContent = String(l.label);
      wrap.appendChild(a);
    });
    log.appendChild(wrap);
  }

  function addContact(contact) {
    if (!contact || !contact.label) return;
    var wrap = document.createElement("div");
    wrap.className = "companion-contact";
    wrap.appendChild(document.createTextNode(String(contact.label)));
    if (contact.value) {
      wrap.appendChild(document.createTextNode(" : "));
      var value = String(contact.value);
      if (contact.is_email && value.indexOf("@") > 0 && /\s/.test(value) === false) {
        var a = document.createElement("a");
        a.href = "mailto:" + value;
        a.textContent = value;
        wrap.appendChild(a);
      } else {
        wrap.appendChild(document.createTextNode(value));
      }
    }
    log.appendChild(wrap);
  }

  function addBotReply(data) {
    // Structured reply: short answer, app chips, numbered steps (textContent only).
    var el = document.createElement("div");
    el.className = "companion-msg companion-msg--bot companion-msg--rich";
    var answer = String((data && data.answer) || "").trim();
    if (answer) {
      var p = document.createElement("p");
      p.className = "companion-answer";
      p.textContent = answer;
      el.appendChild(p);
    }
    var apps = (data && data.apps) || [];
    if (apps.length) {
      var list = document.createElement("ul");
      list.className = "companion-apps";
      list.setAttribute("aria-label", "Applications");
      apps.forEach(function (app) {
        if (!app || !app.label) return;
        var li = document.createElement("li");
        li.className = "companion-app" + (app.openable === false ? " companion-app--locked" : "");
        li.textContent = String(app.label);
        if (app.openable === false) li.title = "Accès en lecture seule";
        list.appendChild(li);
      });
      el.appendChild(list);
    }
    var steps = (data && data.steps) || [];
    if (steps.length) {
      var ol = document.createElement("ol");
      ol.className = "companion-steps";
      steps.forEach(function (step) {
        var li = document.createElement("li");
        li.textContent = String(step);
        ol.appendChild(li);
      });
      el.appendChild(ol);
    }
    if (!el.childNodes.length) return;
    log.appendChild(el);
  }

  function renderReply(data) {
    addBotReply(data);
    addNotices(data && data.notices);
    addLinks(data && data.links);
    addContact(data && data.contact);
    scrollDown();
  }

  function setBusy(state) {
    busy = state;
    sendBtn.disabled = state;
    input.disabled = state;
  }

  function send(text) {
    text = (text || "").trim();
    if (!text || busy) return;
    if (text.length > maxChars) text = text.slice(0, maxChars);
    if (chips) chips.hidden = true;
    addMessage("user", text);
    var pending = addMessage("bot", attr("data-msg-thinking"), "companion-msg--pending");
    setBusy(true);
    var payload = { message: text, history: history.slice(-MAX_HISTORY) };

    // X-Bastion-Busy: 0 keeps the global page spinner out of the chat.
    fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-CSRF-Token": csrfToken(),
        "X-Bastion-Busy": "0",
      },
      body: JSON.stringify(payload),
    })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (body) {
          return { status: res.status, body: body };
        });
      })
      .then(function (r) {
        pending.remove();
        if (r.status === 401) {
          addMessage("bot", attr("data-msg-expired"));
        } else if (r.status === 200) {
          renderReply(r.body);
          history.push({ role: "user", content: text });
          var said = String(r.body.answer || "");
          var appNames = (r.body.apps || []).map(function (a) { return a && a.label; }).filter(Boolean);
          if (appNames.length) said += " Applications : " + appNames.join(", ") + ".";
          if ((r.body.steps || []).length) said += " Étapes : " + r.body.steps.join(" ; ");
          history.push({ role: "assistant", content: said.slice(0, 500) });
          history = history.slice(-MAX_HISTORY);
        } else {
          addMessage("bot", String((r.body && r.body.message) || attr("data-msg-error")));
        }
      })
      .catch(function () {
        pending.remove();
        addMessage("bot", attr("data-msg-error"));
      })
      .then(function () {
        setBusy(false);
        input.value = "";
        input.focus();
      });
  }

  toggle.addEventListener("click", function () {
    if (panel.hidden) open();
    else close();
  });
  closeBtn.addEventListener("click", close);
  root.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !panel.hidden) close();
  });
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    send(input.value);
  });
  input.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      send(input.value);
    }
  });
  Array.prototype.forEach.call(root.querySelectorAll("[data-companion-chip]"), function (chip) {
    chip.addEventListener("click", function () {
      send(chip.textContent);
    });
  });
})();
