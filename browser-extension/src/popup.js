// Popup: shows the state of the connection to the app and the logins for
// the current site. It never receives passwords: filling happens in the
// background, straight into the page.
const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const msg = (key, ...subs) => api.i18n.getMessage(key, subs.map(String)) || key;

const VIEWS = ['loading', 'no_host', 'no_app', 'no_vault', 'pair', 'pairing', 'locked', 'unlocked', 'error'];
let tab = null;
let pollTimer = null;

for (const el of document.querySelectorAll('[data-msg]')) el.textContent = msg(el.dataset.msg);
for (const el of document.querySelectorAll('[data-msg-title]')) el.title = msg(el.dataset.msgTitle);
for (const el of document.querySelectorAll('[data-msg-aria]')) el.setAttribute('aria-label', msg(el.dataset.msgAria));
document.documentElement.lang = api.i18n.getUILanguage();
const manifest = api.runtime.getManifest();
$('version').textContent = `v${manifest.version_name ?? manifest.version}`;

const send = (message) => api.runtime.sendMessage(message);
const errorText = (r) => {
  const key = `err_${r?.code ?? 'internal_error'}`;
  const text = api.i18n.getMessage(key);
  return text || r?.message || msg('err_internal_error');
};
const status = (text, kind) => { $('status').textContent = text ?? ''; $('status').className = kind ?? ''; };

function showView(name) {
  for (const v of VIEWS) $(`v-${v}`).hidden = v !== name;
  $('lock').hidden = name !== 'unlocked';
}

async function refresh() {
  clearTimeout(pollTimer);
  const state = await send({ type: 'state' });
  showView(state.view);
  switch (state.view) {
    case 'pairing':
      $('pair-code').textContent = state.code;
      pollTimer = setTimeout(refresh, 1500); // until the app answers
      break;
    case 'pair':
      if (state.code) status(errorText({ code: state.code }), 'error');
      $('pair').focus();
      break;
    case 'locked':
      $('password').focus();
      break;
    case 'unlocked':
      await loadMatches();
      break;
    case 'error':
      $('error-text').textContent = errorText(state);
      break;
    default:
      break;
  }
}

// ------------------------------------------------------------- entries
function entryButton(entry, onChoose) {
  const li = document.createElement('li');
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'entry';
  const title = document.createElement('span');
  title.className = 'title';
  title.textContent = entry.title;
  const sub = document.createElement('span');
  sub.className = 'sub';
  sub.textContent = [entry.username, entry.site].filter(Boolean).join(' · ');
  button.append(title, sub);
  button.addEventListener('click', () => onChoose(entry));
  li.append(button);
  return li;
}

async function loadMatches() {
  const result = await send({ type: 'matches', tabId: tab?.id });
  $('matches').replaceChildren();
  if (!result.ok) {
    $('site').textContent = '';
    $('no-matches').hidden = true;
    if (result.code === 'locked') { await refresh(); return; }
    status(errorText(result), result.code === 'unsupported_page' ? '' : 'error');
    $('search').focus();
    return;
  }
  $('site').textContent = result.site.domain;
  $('no-matches').hidden = result.entries.length > 0;
  const alike = result.lookalikes ?? [];
  $('lookalike').hidden = alike.length === 0;
  $('lookalike').textContent = alike.length ? msg('lookalikeWarning', alike.join(', ')) : '';
  for (const entry of result.entries) $('matches').append(entryButton(entry, (e) => fill(e, false)));
  const first = $('matches').querySelector('button');
  (first ?? $('search')).focus();
}

let searchTimer = null;
$('search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    const query = $('search').value.trim();
    $('results').replaceChildren();
    if (!query) return;
    const result = await send({ type: 'search', tabId: tab?.id, query });
    if (!result.ok) { status(errorText(result), 'error'); return; }
    for (const entry of result.entries) {
      $('results').append(entryButton(entry, (e) => (e.match === 'none' ? confirmMismatch(e) : fill(e, false))));
    }
    if (!result.entries.length) status(msg('noResults'));
    else status('');
  }, 200);
});

// A login saved for another site: warn before filling (phishing, spec §8.5).
let confirming = null;
function confirmMismatch(entry) {
  confirming = entry;
  $('confirm-text').textContent = msg('mismatchWarning', entry.site || '?', $('site').textContent || '?');
  $('confirm').hidden = false;
  $('confirm-no').focus();
}
$('confirm-no').addEventListener('click', () => { confirming = null; $('confirm').hidden = true; $('search').focus(); });
$('confirm-yes').addEventListener('click', () => {
  const entry = confirming;
  confirming = null;
  $('confirm').hidden = true;
  if (entry) fill(entry, true);
});

async function fill(entry, allowMismatch) {
  status(msg('filling'));
  const result = await send({ type: 'fill', tabId: tab?.id, entryId: entry.id, allowMismatch });
  if (result.ok) { window.close(); return; }
  if (result.code === 'site_mismatch') { confirmMismatch({ ...entry, site: result.site ?? entry.site }); status(''); return; }
  status(errorText(result), 'error');
}

// ------------------------------------------------------------- actions
$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('password').value.normalize('NFC');
  if (!password) return;
  const button = $('unlock-form').querySelector('button');
  button.disabled = true;
  status(msg('unlocking'));
  const result = await send({ type: 'unlock', password });
  $('password').value = '';
  button.disabled = false;
  if (!result.ok) { status(errorText(result), 'error'); $('password').focus(); return; }
  status('');
  await refresh();
});

$('pair').addEventListener('click', async () => {
  status('');
  const result = await send({ type: 'pair' });
  if (!result.ok) {
    if (result.code === 'app_unavailable') { showView('no_app'); return; }
    status(errorText(result), 'error');
    return;
  }
  await refresh();
});

$('launch').addEventListener('click', async () => {
  const result = await send({ type: 'launch_app' });
  if (!result.ok) { status(errorText(result), 'error'); return; }
  status(msg('starting'));
  setTimeout(async () => { status(''); await refresh(); }, 2500);
});

$('lock').addEventListener('click', async () => {
  const result = await send({ type: 'lock' });
  if (!result.ok) status(errorText(result), 'error');
  await refresh();
});

async function generate(kind) {
  const result = await send({ type: 'generate', kind });
  if (!result.ok) { status(errorText(result), 'error'); return; }
  status(result.copied ? msg('generatedCopied', result.clearsIn) : errorText({ code: 'clipboard_error' }), result.copied ? 'ok' : 'error');
}
$('gen-password').addEventListener('click', () => generate('password'));
$('gen-passphrase').addEventListener('click', () => generate('passphrase'));

$('retry').addEventListener('click', () => { status(''); refresh(); });
$('options').addEventListener('click', () => api.runtime.openOptionsPage());

// ------------------------------------------------------------ save login
// The background reads what was typed in the page and keeps the password;
// the popup only shows and edits the title and username.
let saveAction = null;
function showSavePanel(offer) {
  saveAction = offer.action;
  $('save-panel').hidden = false;
  $('save-text').textContent = offer.action === 'update' ? msg('saveUpdateText', offer.title)
    : offer.action === 'unchanged' ? msg('saveUnchangedText', offer.title)
    : msg('saveAddText', offer.site);
  $('save-lookalike').hidden = !offer.lookalikes?.length;
  $('save-lookalike').textContent = offer.lookalikes?.length ? msg('lookalikeWarning', offer.lookalikes.join(', ')) : '';
  $('save-title-row').hidden = offer.action !== 'add';
  $('save-title').value = offer.title ?? '';
  $('save-username').value = offer.username ?? '';
  $('save-username').readOnly = offer.action !== 'add'; // an update keeps the saved username
  $('save-confirm').textContent = msg(offer.action === 'add' ? 'save' : 'updatePassword');
  $('save-confirm').hidden = offer.action === 'unchanged';
  (offer.action === 'add' ? $('save-title') : $('save-confirm')).focus();
}
function hideSavePanel() {
  saveAction = null;
  $('save-panel').hidden = true;
}

$('save-login').addEventListener('click', async () => {
  status('');
  const offer = await send({ type: 'capture', tabId: tab?.id });
  if (!offer.ok) { status(errorText(offer), 'error'); return; }
  showSavePanel(offer);
});
$('save-cancel').addEventListener('click', async () => {
  hideSavePanel();
  await send({ type: 'discard_save', tabId: tab?.id });
});
$('save-confirm').addEventListener('click', async () => {
  if (!saveAction) return;
  $('save-confirm').disabled = true;
  const result = await send({ type: 'save', tabId: tab?.id, title: $('save-title').value.trim(),
                              username: $('save-username').value.trim() });
  $('save-confirm').disabled = false;
  if (!result.ok) { status(errorText(result), 'error'); return; }
  hideSavePanel();
  status(msg(result.action === 'updated' ? 'savedUpdated' : 'savedAdded'), 'ok');
  await loadMatches();
});

// ---------------------------------------------------------------- start
[tab] = await api.tabs.query({ active: true, currentWindow: true });
await refresh();
