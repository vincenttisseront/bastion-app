/* Shared WebAuthn base64url helpers (admin MFA challenge + profile register). */
(function (global) {
  function b64urlToBuf(b64url) {
    var pad = '='.repeat((4 - (b64url.length % 4)) % 4);
    var b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
    var str = atob(b64);
    var buf = new ArrayBuffer(str.length);
    var view = new Uint8Array(buf);
    for (var i = 0; i < str.length; i++) view[i] = str.charCodeAt(i);
    return buf;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    var s = btoa(str).replace(/\+/g, '-').replace(/\//g, '_');
    var eq = s.indexOf('=');
    return eq === -1 ? s : s.slice(0, eq);
  }

  global.BastionWebAuthnB64 = { b64urlToBuf: b64urlToBuf, bufToB64url: bufToB64url };
})(window);
