// Functions run inside the web page with scripting.executeScript (in the
// extension's isolated world, not visible to the page's own scripts). Each
// must be self-contained: the browser serializes its source.

// Where are the login fields? Run in every frame of the tab.
export function probeLoginForm() {
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
    getComputedStyle(el).visibility !== 'hidden';
  const usable = (el) => visible(el) && !el.disabled && !el.readOnly;
  const passwords = [...document.querySelectorAll('input[type=password]')].filter(usable);
  const texts = [...document.querySelectorAll('input')].filter((el) => usable(el) &&
    ['', 'text', 'email', 'tel'].includes((el.getAttribute('type') || '').toLowerCase()));
  return { origin: location.origin, url: location.href, top: window === window.top,
           passwords: passwords.length, texts: texts.length };
}

// Fills the username and password fields of this frame. Never submits the
// form (spec §8.5). `expectedOrigin` guards against the frame having
// navigated away since the credentials were requested.
export function fillLoginForm(username, password, expectedOrigin) {
  if (location.origin !== expectedOrigin) return { filled: false, reason: 'origin_changed' };
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
    getComputedStyle(el).visibility !== 'hidden';
  const usable = (el) => visible(el) && !el.disabled && !el.readOnly;
  const textLike = (el) => ['', 'text', 'email', 'tel'].includes((el.getAttribute('type') || '').toLowerCase());

  const passwords = [...document.querySelectorAll('input[type=password]')].filter(usable);
  const pw = passwords.find((el) => el.autocomplete === 'current-password') ||
             passwords.find((el) => el.autocomplete !== 'new-password') || passwords[0] || null;

  const scope = (pw && pw.form) || document;
  const texts = [...scope.querySelectorAll('input')].filter((el) => usable(el) && textLike(el));
  let user = texts.find((el) => el.autocomplete === 'username') || null;
  if (!user && pw) {
    // The last text field before the password field.
    user = texts.filter((el) => el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING).pop() || null;
  }
  if (!user && !pw) {
    // Username-first sign-in pages.
    user = texts.find((el) => /user|email|login|account|ident/i.test(`${el.name} ${el.id} ${el.autocomplete}`)) ||
           (texts.length === 1 ? texts[0] : null);
  }

  // Set the value the way typing would, so frameworks notice the change.
  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const set = (el, value) => {
    el.focus();
    valueSetter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (user && username) set(user, username);
  if (pw && password) set(pw, password);
  if (pw) pw.focus();
  return { filled: !!(user || pw), username: !!user, password: !!pw };
}
