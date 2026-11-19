// Optional automatic detection (enabled in the extension options, which
// grants access to all sites): notices when a login form is sent and shows a
// bar offering to save it. Runs after capture.js in the isolated world.
(() => {
  if (globalThis.__phylaxboxDetect) return;
  globalThis.__phylaxboxDetect = true;
  const api = globalThis.browser ?? globalThis.chrome;
  const msg = (key, ...subs) => api.i18n.getMessage(key, subs.map(String)) || key;
  let lastSent = 0;

  function report(root) {
    const login = globalThis.__phylaxboxCapture(root);
    if (!login || Date.now() - lastSent < 1500) return;
    lastSent = Date.now();
    api.runtime.sendMessage({ type: 'login_submitted', username: login.username, password: login.password })
      .catch(() => {});
  }

  // Forms sent the classic way, and script-driven sign-ins (a button click or
  // Enter in a filled password field).
  document.addEventListener('submit', (event) => report(event.target), true);
  document.addEventListener('click', (event) => {
    const button = event.target instanceof Element &&
      event.target.closest('button, input[type=submit], input[type=button], [role=button]');
    if (!button) return;
    const form = button.closest('form') || document;
    if (form.querySelector('input[type=password]')) report(form);
  }, true);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement && event.target.type === 'password') {
      report(event.target.form || document);
    }
  }, true);

  if (window !== window.top) return; // the bar only in the top frame

  let host = null;
  function closeBar() {
    if (host) host.remove();
    host = null;
  }

  // In a closed shadow root: the page's scripts and styles cannot reach it.
  function showBar(offer) {
    closeBar();
    host = document.createElement('div');
    host.style.cssText = 'all: initial; position: fixed; top: 12px; right: 12px; z-index: 2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      .bar { font: 14px/1.4 system-ui, "Segoe UI", sans-serif; color: #1d2330; background: #fff; width: 320px;
             border: 1px solid #c4cad4; border-radius: 10px; padding: 12px 14px; box-shadow: 0 6px 24px rgba(0,0,0,.18); }
      .title { font-weight: 600; margin: 0 0 6px; }
      p { margin: 0 0 8px; }
      .warn { padding: 6px 8px; border-radius: 6px; background: #fff6e5; color: #7a4b00; }
      .actions { display: flex; gap: 8px; justify-content: flex-end; }
      button { font: inherit; padding: 6px 10px; border-radius: 6px; cursor: pointer; border: 1px solid #c4cad4;
               background: transparent; color: inherit; }
      button.primary { background: #2f5bd3; border-color: #2f5bd3; color: #fff; font-weight: 600; }
      @media (prefers-color-scheme: dark) {
        .bar { color: #e8eaf0; background: #1d212a; border-color: #4a5568; }
        .warn { background: #3a2c12; color: #f3c56b; }
        button { border-color: #4a5568; }
        button.primary { background: #7b9cff; border-color: #7b9cff; color: #0b1020; }
      }`;
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.setAttribute('role', 'dialog');
    const title = document.createElement('p');
    title.className = 'title';
    title.textContent = 'PhylaxBox';
    const text = document.createElement('p');
    text.textContent = offer.action === 'update'
      ? msg('offerUpdate', offer.title, offer.username || '—')
      : msg('offerAdd', offer.username || '—', offer.site);
    bar.append(title, text);
    if (offer.lookalikes?.length) {
      const warn = document.createElement('p');
      warn.className = 'warn';
      warn.textContent = msg('lookalikeWarning', offer.lookalikes.join(', '));
      bar.append(warn);
    }
    const actions = document.createElement('div');
    actions.className = 'actions';
    const no = document.createElement('button');
    no.textContent = msg('notNow');
    const yes = document.createElement('button');
    yes.className = 'primary';
    yes.textContent = msg(offer.action === 'update' ? 'updatePassword' : 'save');
    const answer = (save) => {
      closeBar();
      api.runtime.sendMessage({ type: 'offer_answer', save }).catch(() => {});
    };
    no.addEventListener('click', () => answer(false));
    yes.addEventListener('click', (event) => { if (event.isTrusted) answer(true); });
    actions.append(no, yes);
    bar.append(actions);
    root.append(style, bar);
    document.documentElement.append(host);
  }

  api.runtime.onMessage.addListener((message) => {
    if (message?.type === 'offer_save') showBar(message.offer);
  });
  // The sign-in may have moved to another page: pick up a pending offer.
  api.runtime.sendMessage({ type: 'offer_query' }).then((reply) => {
    if (reply?.offer) showBar(reply.offer);
  }).catch(() => {});
})();
