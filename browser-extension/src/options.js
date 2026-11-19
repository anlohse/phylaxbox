// Extension options: the optional automatic detection of logins to save.
// Turning it on asks the browser for access to all http(s) sites; turning it
// off gives that access back.
const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const msg = (key) => api.i18n.getMessage(key) || key;
const SITE_PATTERNS = ['http://*/*', 'https://*/*'];

for (const el of document.querySelectorAll('[data-msg]')) el.textContent = msg(el.dataset.msg);
document.documentElement.lang = api.i18n.getUILanguage();

const status = (text, kind) => { $('status').textContent = text ?? ''; $('status').className = kind ?? ''; };
const send = (message) => api.runtime.sendMessage(message);

$('auto-save').checked = (await send({ type: 'get_options' }))?.autoSave === true;

$('auto-save').addEventListener('change', async () => {
  const enable = $('auto-save').checked;
  status('');
  if (enable) {
    // Must be asked from the click itself (a user gesture).
    let granted = false;
    try { granted = await api.permissions.request({ origins: SITE_PATTERNS }); } catch { granted = false; }
    if (!granted) {
      $('auto-save').checked = false;
      status(msg('autoSaveDenied'), 'error');
      return;
    }
  }
  const result = await send({ type: 'set_auto_save', enabled: enable });
  if (!enable) {
    try { await api.permissions.remove({ origins: SITE_PATTERNS }); } catch { /* already gone */ }
  }
  $('auto-save').checked = result?.enabled === true;
  status(msg(result?.enabled ? 'autoSaveOn' : 'autoSaveOff'), 'ok');
});
