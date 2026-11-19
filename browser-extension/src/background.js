// PhylaxBox extension background (spec §8).
//
// The extension never decrypts or stores the vault: every request goes to the
// desktop app through the native messaging host (spec §8.3, §9), after the
// extension has authenticated with the key it got when the user approved it
// in the app (docs/browser-integration/protocol.md). Passwords pass through
// here only on their way into the page, and only for the tab the user acted
// on (activeTab), never to the popup.

import { authMessage, equalBytes, fromBase64, hmacSha256, randomBytes, toBase64 } from './auth.js';
import { fillLoginForm, probeLoginForm } from './page.js';

const api = globalThis.browser ?? globalThis.chrome;
export const NATIVE_HOST = 'com.phylaxbox.native_host';
const REQUEST_TIMEOUT_MS = 20000;      // unlocking runs Argon2id in the app
const IDLE_DISCONNECT_MS = 60000;      // sessions end when not used
const PAIR_POLL_MS = 1000;
const OFFER_LIFETIME_MS = 120000;      // a typed password is kept at most this long

// Login pages, for the optional automatic detection (extension options).
const SITE_PATTERNS = ['http://*/*', 'https://*/*'];
const DETECT_SCRIPT_ID = 'phylaxbox-detect';

// ------------------------------------------------------------ native port
let port = null;
let nextId = 1;
const pending = new Map();             // id -> {resolve, timer}
let authenticated = false;
let idleTimer = null;
let pairing = null;                    // {state: 'pending'|'approved'|'failed', pairingId?, code?, error?}

function connect() {
  const p = api.runtime.connectNative(NATIVE_HOST);
  port = p;
  authenticated = false;
  p.onMessage.addListener((message) => {
    const entry = pending.get(message?.id);
    if (!entry) return;
    pending.delete(message.id);
    clearTimeout(entry.timer);
    entry.resolve(message);
  });
  p.onDisconnect.addListener(() => {
    // Chrome reports why in runtime.lastError, Firefox in port.error.
    const reason = String(api.runtime.lastError?.message ?? p.error?.message ?? '');
    const code = /not found|no such native application|not registered|forbidden|access/i.test(reason)
      ? 'host_missing' : 'host_disconnected';
    if (port === p) {
      port = null;
      authenticated = false;
    }
    for (const [id, entry] of pending) {
      clearTimeout(entry.timer);
      entry.resolve({ id, ok: false, code, message: reason });
    }
    pending.clear();
  });
}

function closePort() {
  if (!port) return;
  const p = port;
  port = null;
  authenticated = false;
  p.disconnect();
  for (const [id, entry] of pending) {
    clearTimeout(entry.timer);
    entry.resolve({ id, ok: false, code: 'host_disconnected' });
  }
  pending.clear();
}

// Closing the port ends the app-side session: the next use authenticates again.
function keepAlive() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (pairing?.state !== 'pending') closePort();
  }, IDLE_DISCONNECT_MS);
}

// One message to the native host; resolves with its reply (never rejects).
function request(type, params = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  if (!port) {
    try { connect(); } catch (error) {
      return Promise.resolve({ ok: false, code: 'host_missing', message: String(error) });
    }
  }
  keepAlive();
  const id = nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ id, ok: false, code: 'timeout' });
    }, timeoutMs);
    pending.set(id, { resolve, timer });
    try {
      port.postMessage({ ...params, id, type });
    } catch (error) {
      clearTimeout(timer);
      pending.delete(id);
      resolve({ id, ok: false, code: 'host_disconnected', message: String(error) });
    }
  });
}

// ------------------------------------------------- pairing, authentication
function browserName() {
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return 'Edge';
  if (/OPR\//.test(ua)) return 'Opera';
  if (/Firefox\//.test(ua)) return 'Firefox';
  if (navigator.brave) return 'Brave';
  if (/Chrome\//.test(ua)) return 'Chrome';
  return 'Browser';
}

async function storedPairing() {
  const { pairing: stored } = await api.storage.local.get('pairing');
  return stored?.clientId && stored?.key ? stored : null;
}

async function forgetPairing() {
  authenticated = false;
  await api.storage.local.remove('pairing');
}

async function authenticate() {
  if (authenticated && port) return { ok: true };
  const stored = await storedPairing();
  if (!stored) return { ok: false, code: 'not_paired' };
  const begin = await request('auth_begin', { clientId: stored.clientId });
  if (!begin.ok) {
    if (begin.code === 'not_paired') await forgetPairing();
    return begin;
  }
  const key = fromBase64(stored.key);
  const serverChallenge = fromBase64(begin.challenge);
  const clientChallenge = randomBytes(32);
  const proof = await hmacSha256(key, authMessage('client', serverChallenge, clientChallenge));
  const finish = await request('auth_finish', {
    clientId: stored.clientId, clientChallenge: toBase64(clientChallenge), proof: toBase64(proof),
  });
  if (!finish.ok) {
    if (finish.code === 'auth_failed' || finish.code === 'not_paired') await forgetPairing();
    return finish;
  }
  // The app must prove it holds the same key (it is not an impostor).
  const expected = await hmacSha256(key, authMessage('server', serverChallenge, clientChallenge));
  if (!equalBytes(expected, fromBase64(finish.serverProof ?? ''))) {
    closePort();
    return { ok: false, code: 'app_not_trusted' };
  }
  authenticated = true;
  return { ok: true };
}

// An authenticated request (authenticating first when needed).
async function call(type, params = {}, timeoutMs) {
  let auth = await authenticate();
  if (!auth.ok) return auth;
  let reply = await request(type, params, timeoutMs);
  if (!reply.ok && reply.code === 'not_authenticated') { // the app restarted
    authenticated = false;
    auth = await authenticate();
    if (!auth.ok) return auth;
    reply = await request(type, params, timeoutMs);
  }
  if (!reply.ok && reply.code === 'not_paired') await forgetPairing(); // removed in the app
  return reply;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function startPairing() {
  if (pairing?.state === 'pending') return { ok: true, code: pairing.code };
  const begin = await request('pair_begin', { browser: browserName() });
  if (!begin.ok) return begin;
  pairing = { state: 'pending', pairingId: begin.pairingId, code: begin.verificationCode };
  pollPairing(); // continues while the popup is closed (the user is in the app)
  return { ok: true, code: pairing.code };
}

async function pollPairing() {
  while (pairing?.state === 'pending') {
    await sleep(PAIR_POLL_MS);
    const status = await request('pair_status', { pairingId: pairing.pairingId });
    if (status.ok && status.state === 'pending') continue;
    if (status.ok && status.state === 'approved') {
      await api.storage.local.set({ pairing: { clientId: status.clientId, key: status.key } });
      authenticated = false;
      pairing = { state: 'approved' };
    } else {
      pairing = { state: 'failed', error: status.code };
    }
  }
}

// ----------------------------------------------------------------- state
// What the popup should show.
async function state() {
  const ping = await request('ping');
  if (!ping.ok) return { view: ping.code === 'host_missing' ? 'no_host' : 'error', code: ping.code };
  if (pairing?.state === 'pending') return { view: 'pairing', code: pairing.code };
  const failedPairing = pairing?.state === 'failed' ? pairing.error : null;
  if (pairing && pairing.state !== 'pending') pairing = null;

  const auth = await authenticate();
  if (!auth.ok) {
    if (auth.code === 'app_unavailable') return { view: 'no_app' };
    if (auth.code === 'not_paired' || auth.code === 'auth_failed') return { view: 'pair', code: failedPairing };
    return { view: 'error', code: auth.code };
  }
  const status = await call('status');
  if (!status.ok) return { view: status.code === 'app_unavailable' ? 'no_app' : 'error', code: status.code };
  if (!status.exists) return { view: 'no_vault' };
  return { view: status.unlocked ? 'unlocked' : 'locked' };
}

// ------------------------------------------------------------------- fill
async function tabUrl(tabId) {
  const tab = await api.tabs.get(tabId);
  return tab?.url ?? '';
}

// Picks the frame to fill: the top frame, or a frame of the same origin.
// Login forms in frames from other origins are not filled (spec §8.5).
async function loginFrame(tabId) {
  let frames;
  try {
    frames = await api.scripting.executeScript({ target: { tabId, allFrames: true }, func: probeLoginForm });
  } catch {
    try {
      frames = await api.scripting.executeScript({ target: { tabId }, func: probeLoginForm });
    } catch {
      return { error: 'page_not_accessible' };
    }
  }
  frames = (frames ?? []).filter((f) => f && f.result);
  const top = frames.find((f) => f.frameId === 0);
  if (!top) return { error: 'page_not_accessible' };
  const withPassword = frames.filter((f) => f.result.passwords > 0);
  const chosen = withPassword.find((f) => f.frameId === 0) ??
                 withPassword.find((f) => f.result.origin === top.result.origin);
  if (chosen) return { frame: chosen };
  if (withPassword.length) return { error: 'untrusted_frame' };
  return { frame: top }; // username-first pages
}

async function fill(tabId, entryId, allowMismatch) {
  const { frame, error } = await loginFrame(tabId);
  if (error) return { ok: false, code: error };
  const creds = await call('credentials', { entryId, url: frame.result.url, allowMismatch: !!allowMismatch });
  if (!creds.ok) return creds;
  let results;
  try {
    results = await api.scripting.executeScript({
      target: { tabId, frameIds: [frame.frameId] },
      func: fillLoginForm,
      args: [creds.username, creds.password, frame.result.origin],
    });
  } catch {
    return { ok: false, code: 'page_not_accessible' };
  } finally {
    creds.username = '';
    creds.password = '';
  }
  const outcome = results?.[0]?.result;
  if (!outcome?.filled) return { ok: false, code: outcome?.reason === 'origin_changed' ? 'page_changed' : 'no_login_form' };
  return { ok: true, match: creds.match };
}

// ------------------------------------------------------------------- save
// Logins typed in a page, waiting for the user's answer (per tab). The
// password stays here, never in the popup or the page's bar.
const pendingSaves = new Map(); // tabId -> {url, username, password, preview, expires}

function livePending(tabId) {
  const pending = pendingSaves.get(tabId);
  if (pending && pending.expires > Date.now()) return pending;
  pendingSaves.delete(tabId);
  return null;
}

// What the popup or the bar may see of a pending save (no password).
function publicOffer(pending) {
  const p = pending.preview;
  return { action: p.action, title: p.title, site: p.site, username: pending.username,
           lookalikes: p.lookalikes ?? [] };
}

async function preview(tabId, url, username, password) {
  const result = await call('save_preview', { url, username, password });
  if (!result.ok) return result;
  pendingSaves.set(tabId, { url, username, password, preview: result, expires: Date.now() + OFFER_LIFETIME_MS });
  return { ok: true, ...publicOffer(pendingSaves.get(tabId)) };
}

// The popup's "Save this login": read what was typed in the tab.
async function captureLogin(tabId) {
  let frames;
  try {
    await api.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['capture.js'] });
    frames = await api.scripting.executeScript({
      target: { tabId, allFrames: true }, func: () => globalThis.__phylaxboxCapture(document),
    });
  } catch {
    return { ok: false, code: 'page_not_accessible' };
  }
  frames = (frames ?? []).filter((f) => f && f.result);
  const top = await api.tabs.get(tabId);
  const topOrigin = top?.url ? new URL(top.url).origin : '';
  const login = frames.find((f) => f.frameId === 0)?.result ??
                frames.find((f) => f.result.origin === topOrigin)?.result;
  if (!login) return { ok: false, code: frames.length ? 'untrusted_frame' : 'no_login_data' };
  return preview(tabId, login.url, login.username, login.password);
}

async function confirmSave(tabId, title, username) {
  const pending = livePending(tabId);
  pendingSaves.delete(tabId);
  if (!pending) return { ok: false, code: 'save_expired' };
  const params = { url: pending.url, username: username ?? pending.username, password: pending.password };
  if (pending.preview.action === 'update' || pending.preview.action === 'unchanged') {
    params.entryId = pending.preview.entryId;
  } else if (title) {
    params.title = title;
  }
  pending.password = '';
  return call('save', params);
}

// ------------------------------------------------- automatic detection
async function detectionWanted() {
  const { autoSave } = await api.storage.local.get('autoSave');
  return autoSave === true && (await api.permissions.contains({ origins: SITE_PATTERNS }));
}

// Keeps the registered content scripts in line with the option (and with
// the site permission, which the user can withdraw in the browser).
async function syncDetection() {
  const wanted = await detectionWanted();
  const registered = await api.scripting.getRegisteredContentScripts({ ids: [DETECT_SCRIPT_ID] });
  if (wanted && !registered.length) {
    await api.scripting.registerContentScripts([{
      id: DETECT_SCRIPT_ID, matches: SITE_PATTERNS, js: ['capture.js', 'detect.js'],
      allFrames: true, runAt: 'document_idle',
    }]);
  } else if (!wanted && registered.length) {
    await api.scripting.unregisterContentScripts({ ids: [DETECT_SCRIPT_ID] });
  }
  return { ok: true, enabled: wanted };
}

async function setAutoSave(enabled) {
  await api.storage.local.set({ autoSave: enabled === true });
  return syncDetection();
}

api.permissions.onRemoved.addListener(() => { syncDetection().catch(() => {}); });
syncDetection().catch(() => {});

// Messages from detect.js in web pages: untrusted input. Only the login the
// user just sent in that tab is considered, and saving needs a click on the
// bar (a trusted event in the top frame).
async function handleContent(message, sender) {
  if (!(await detectionWanted())) return null;
  const tabId = sender.tab.id;
  switch (message?.type) {
    case 'login_submitted': {
      const url = String(sender.url ?? '');
      if (sender.frameId !== 0) {
        const topOrigin = sender.tab.url ? new URL(sender.tab.url).origin : '';
        if (!url || new URL(url).origin !== topOrigin) return null; // frames of other sites
      }
      const username = String(message.username ?? '').slice(0, 1024);
      const password = String(message.password ?? '');
      if (!password || password.length > 4096) return null;
      // Never pair or unlock from a page: only when the session is usable.
      const auth = await authenticate();
      if (!auth.ok) return null;
      const offer = await preview(tabId, url, username, password);
      if (!offer.ok || offer.action === 'unchanged') {
        pendingSaves.delete(tabId);
        return null;
      }
      api.tabs.sendMessage(tabId, { type: 'offer_save', offer }, { frameId: 0 }).catch(() => {});
      return null;
    }
    case 'offer_query': {
      const pending = sender.frameId === 0 ? livePending(tabId) : null;
      return pending && pending.preview.action !== 'unchanged' ? { offer: publicOffer(pending) } : null;
    }
    case 'offer_answer': {
      if (sender.frameId !== 0) return null;
      if (message.save !== true) {
        pendingSaves.delete(tabId);
        return null;
      }
      const result = await confirmSave(tabId, null, null);
      if (result.ok) {
        api.action.setBadgeText({ text: '✓', tabId });
        setTimeout(() => api.action.setBadgeText({ text: '', tabId }), 3000);
      }
      return null;
    }
    default:
      return null;
  }
}

api.tabs.onRemoved.addListener((tabId) => pendingSaves.delete(tabId));

// ---------------------------------------------------------------- popup
async function handle(message) {
  const tabId = Number.isInteger(message?.tabId) ? message.tabId : null;
  switch (message?.type) {
    case 'state': return state();
    case 'pair': return startPairing();
    case 'launch_app': return request('launch_app');
    case 'unlock': return call('unlock', { password: String(message.password ?? '') }, 60000);
    case 'lock': return call('lock');
    case 'matches': {
      if (tabId === null) return { ok: false, code: 'bad_request' };
      const url = await tabUrl(tabId);
      return call('matches', { url });
    }
    case 'search': {
      if (tabId === null) return { ok: false, code: 'bad_request' };
      const url = await tabUrl(tabId);
      return call('search', { query: String(message.query ?? '').slice(0, 200), url: url || null });
    }
    case 'fill':
      if (tabId === null || typeof message.entryId !== 'string') return { ok: false, code: 'bad_request' };
      return fill(tabId, message.entryId, message.allowMismatch === true);
    case 'generate': {
      const options = message.kind === 'passphrase' ? { kind: 'passphrase', words: 6 } : { kind: 'password', length: 20 };
      return call('generate', { options, copy: true });
    }
    case 'capture':
      if (tabId === null) return { ok: false, code: 'bad_request' };
      return captureLogin(tabId);
    case 'pending_save': {
      const pending = tabId === null ? null : livePending(tabId);
      return pending ? { ok: true, ...publicOffer(pending) } : { ok: false };
    }
    case 'save':
      if (tabId === null) return { ok: false, code: 'bad_request' };
      return confirmSave(tabId, typeof message.title === 'string' ? message.title.slice(0, 1024) : null,
                         typeof message.username === 'string' ? message.username.slice(0, 1024) : null);
    case 'discard_save':
      if (tabId !== null) pendingSaves.delete(tabId);
      return { ok: true };
    case 'get_options': return { ok: true, autoSave: await detectionWanted() };
    case 'set_auto_save': return setAutoSave(message.enabled === true);
    case 'forget': await forgetPairing(); return { ok: true };
    default: return { ok: false, code: 'bad_request' };
  }
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== api.runtime.id) return false;
  // The extension's own popup and options pages (the options page may live
  // in a tab, so the URL decides, not sender.tab).
  const url = String(sender.url ?? '');
  const ownPage = [api.runtime.getURL('popup.html'), api.runtime.getURL('options.html')].some((p) => url.startsWith(p));
  if (ownPage) {
    handle(message).then(sendResponse, (error) => sendResponse({ ok: false, code: 'internal_error', message: String(error) }));
    return true; // async response
  }
  if (sender.tab && !url.startsWith(api.runtime.getURL(''))) { // detect.js in a web page
    handleContent(message, sender).then(sendResponse, () => sendResponse(null));
    return true;
  }
  return false;
});

// Keyboard shortcut: fill when exactly one login matches; otherwise the popup.
api.commands.onCommand.addListener(async (command, tab) => {
  if (command !== 'fill-login') return;
  const target = tab ?? (await api.tabs.query({ active: true, currentWindow: true }))[0];
  if (target?.id !== undefined && target.url) {
    const found = await call('matches', { url: target.url });
    if (found.ok && found.entries.length === 1) {
      const result = await fill(target.id, found.entries[0].id, false);
      if (result.ok) return;
    }
  }
  try {
    await api.action.openPopup();
  } catch {
    // Not allowed here: point at the toolbar button instead.
    api.action.setBadgeText({ text: '!', tabId: target?.id });
    setTimeout(() => api.action.setBadgeText({ text: '', tabId: target?.id }), 4000);
  }
});
