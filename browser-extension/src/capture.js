// Reads the login the user typed in a page: the username and password
// fields with values. Classic script (not a module) run in the extension's
// isolated world, both by scripting.executeScript (the popup's "save" button)
// and as part of the optional automatic detection (detect.js). It defines a
// global in that world only; the page's own scripts cannot see it.
globalThis.__phylaxboxCapture = function capture(root) {
  const scope = root || document;
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
    getComputedStyle(el).visibility !== 'hidden';
  const textLike = (el) => ['', 'text', 'email', 'tel'].includes((el.getAttribute('type') || '').toLowerCase());

  const passwords = [...scope.querySelectorAll('input[type=password]')].filter((el) => el.value && visible(el));
  if (!passwords.length) return null;
  // Sign-up and change-password forms: the new password (the last one when
  // it is repeated for confirmation); otherwise the password typed to sign in.
  const fresh = passwords.filter((el) => el.autocomplete === 'new-password');
  let pw = fresh.length ? fresh[fresh.length - 1] : null;
  if (!pw && passwords.length >= 2) {
    const last = passwords[passwords.length - 1];
    const before = passwords[passwords.length - 2];
    if (last.value === before.value) pw = last; // "new password" + "confirm"
  }
  if (!pw) pw = passwords.find((el) => el.autocomplete === 'current-password') || passwords[0];

  const form = pw.form || scope;
  const texts = [...form.querySelectorAll('input')].filter((el) => textLike(el) && el.value && visible(el));
  const user = texts.find((el) => el.autocomplete === 'username') ||
    texts.filter((el) => el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING).pop() ||
    texts.find((el) => /user|email|login|account|ident/i.test(`${el.name} ${el.id}`)) || null;

  return { origin: location.origin, url: location.href, top: window === window.top,
           username: user ? user.value.trim() : '', password: pw.value };
};
