/* Passkey (WebAuthn discoverable credential) — login page + profile enrolment.
 *
 * Login:   [data-passkey-login] → conditional UI (autofill) when supported, and
 *          a modal ceremony on [data-passkey-login-button].
 * Profile: [data-passkey-register] → navigator.credentials.create, then reload.
 *
 * Requires bastion-webauthn-b64.js (BastionWebAuthnB64). No inline script (CSP).
 */
(function () {
  'use strict';

  var B64 = window.BastionWebAuthnB64;
  if (!B64 || !window.PublicKeyCredential || !navigator.credentials) {
    // Unsupported browser: hide the passkey controls, keep the password form.
    var hide = function () {
      document.querySelectorAll('[data-passkey-login], [data-passkey-register-form]').forEach(
        function (el) { el.hidden = true; }
      );
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', hide);
    else hide();
    return;
  }

  function t(s) {
    return window.BastionI18n && typeof window.BastionI18n.t === 'function'
      ? window.BastionI18n.t(s)
      : s;
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) return meta.content;
    var input = document.querySelector('input[name="csrf_token"]');
    return input ? input.value : '';
  }

  function postJson(url, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-CSRF-Token': csrfToken(),
      },
      body: body === undefined ? '{}' : JSON.stringify(body),
    }).then(function (r) {
      return r
        .json()
        .catch(function () { return {}; })
        .then(function (data) { return { ok: r.ok, status: r.status, data: data || {} }; });
    });
  }

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { type: d.type || 'public-key', id: B64.b64urlToBuf(d.id) };
      if (d.transports) out.transports = d.transports;
      return out;
    });
  }

  function requestOptions(json) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
      return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    var o = Object.assign({}, json);
    o.challenge = B64.b64urlToBuf(json.challenge);
    o.allowCredentials = descriptors(json.allowCredentials);
    return o;
  }

  function creationOptions(json) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
      return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    var o = Object.assign({}, json);
    o.challenge = B64.b64urlToBuf(json.challenge);
    o.user = Object.assign({}, json.user, { id: B64.b64urlToBuf(json.user.id) });
    o.excludeCredentials = descriptors(json.excludeCredentials);
    return o;
  }

  function enc(buf) {
    return buf ? B64.bufToB64url(buf) : null;
  }

  function assertionJson(cred) {
    if (typeof cred.toJSON === 'function') return cred.toJSON();
    var r = cred.response;
    return {
      id: cred.id,
      rawId: enc(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: enc(r.clientDataJSON),
        authenticatorData: enc(r.authenticatorData),
        signature: enc(r.signature),
        userHandle: enc(r.userHandle),
      },
    };
  }

  function attestationJson(cred) {
    if (typeof cred.toJSON === 'function') return cred.toJSON();
    var r = cred.response;
    return {
      id: cred.id,
      rawId: enc(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: enc(r.clientDataJSON),
        attestationObject: enc(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
    };
  }

  function isCancel(err) {
    return err && (err.name === 'NotAllowedError' || err.name === 'AbortError');
  }

  // --- Login ---------------------------------------------------------------

  function initLogin(root) {
    var button = root.querySelector('[data-passkey-login-button]');
    var errorBox = root.querySelector('[data-passkey-error]');
    var rd = root.getAttribute('data-rd') || '/apps';
    var conditional = null;
    var busy = false;

    function showError(msg) {
      if (!errorBox) return;
      errorBox.textContent = msg || '';
      errorBox.hidden = !msg;
    }

    function finish(credential) {
      return postJson('/auth/passkey/verify', { credential: assertionJson(credential), rd: rd }).then(
        function (res) {
          if (res.ok && res.data.redirect) {
            window.location.assign(res.data.redirect);
            return;
          }
          throw new Error(res.data.detail || t("Clé d'accès non reconnue."));
        }
      );
    }

    function ceremony(mediation, signal) {
      return postJson('/auth/passkey/options').then(function (res) {
        if (!res.ok) throw new Error(res.data.detail || t('Connexion par clé d\'accès indisponible.'));
        var opts = { publicKey: requestOptions(res.data.options) };
        if (mediation) opts.mediation = mediation;
        if (signal) opts.signal = signal;
        return navigator.credentials.get(opts);
      });
    }

    function startConditional() {
      if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return;
      PublicKeyCredential.isConditionalMediationAvailable()
        .then(function (ok) {
          if (!ok || busy) return;
          conditional = new AbortController();
          return ceremony('conditional', conditional.signal).then(function (cred) {
            if (!cred) return;
            busy = true;
            return finish(cred);
          });
        })
        .catch(function (err) {
          busy = false;
          if (!isCancel(err)) showError(err && err.message);
        });
    }

    if (button) {
      button.addEventListener('click', function () {
        if (busy) return;
        busy = true;
        showError('');
        if (conditional) {
          conditional.abort();
          conditional = null;
        }
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        ceremony(null, null)
          .then(function (cred) {
            if (!cred) throw new Error(t("Clé d'accès non reconnue."));
            return finish(cred);
          })
          .catch(function (err) {
            busy = false;
            button.disabled = false;
            button.removeAttribute('aria-busy');
            if (!isCancel(err)) showError(err && err.message);
          });
      });
    }

    startConditional();
  }

  // --- Profile -------------------------------------------------------------

  function initProfile(root) {
    var button = root.querySelector('[data-passkey-register]');
    var status = root.querySelector('[data-passkey-status]');
    var nameInput = root.querySelector('[data-passkey-name]');
    if (!button) return;

    function setStatus(msg, html) {
      if (!status) return;
      status.textContent = '';
      if (html) status.appendChild(html);
      else status.textContent = msg || '';
      status.hidden = !msg && !html;
    }

    function reauthHint(msg) {
      var frag = document.createDocumentFragment();
      frag.appendChild(document.createTextNode(msg + ' '));
      var link = document.createElement('a');
      link.href = '/logout';
      link.textContent = t('Se reconnecter');
      frag.appendChild(link);
      return frag;
    }

    button.addEventListener('click', function () {
      button.disabled = true;
      setStatus('');
      postJson('/profile/passkeys/register/options')
        .then(function (res) {
          if (!res.ok) {
            var e = new Error(res.data.detail || t('Enregistrement impossible.'));
            e.reauth = !!res.data.reauth;
            throw e;
          }
          return navigator.credentials.create({ publicKey: creationOptions(res.data.options) });
        })
        .then(function (cred) {
          if (!cred) throw new Error(t('Enregistrement impossible.'));
          return postJson('/profile/passkeys/register/verify', {
            credential: attestationJson(cred),
            name: nameInput ? nameInput.value : '',
          });
        })
        .then(function (res) {
          if (!res.ok) throw new Error(res.data.detail || t('Enregistrement impossible.'));
          window.location.hash = '#section-passkeys';
          window.location.reload();
        })
        .catch(function (err) {
          button.disabled = false;
          if (isCancel(err)) return;
          var msg = (err && err.message) || t('Enregistrement impossible.');
          if (err && err.reauth) setStatus(null, reauthHint(msg));
          else setStatus(msg);
        });
    });
  }

  function init() {
    var login = document.querySelector('[data-passkey-login]');
    if (login) initLogin(login);
    var profile = document.querySelector('[data-passkey-profile]');
    if (profile) initProfile(profile);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
