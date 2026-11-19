// Authentication of the extension to the desktop app (see
// docs/browser-integration/protocol.md). The pairing key never leaves this
// browser profile again after pairing; each connection proves knowledge of
// it with HMAC-SHA256 over fresh challenges from both sides, and checks the
// app's proof in return.

export const AUTH_LABEL = 'phylaxbox-browser-auth-v1';
const encoder = new TextEncoder();

export function toBase64(bytes) {
  let text = '';
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text);
}

export function fromBase64(text) {
  const raw = atob(text);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

// "phylaxbox-browser-auth-v1\0client\0" || serverChallenge || clientChallenge
export function authMessage(who, serverChallenge, clientChallenge) {
  const label = encoder.encode(`${AUTH_LABEL}\0${who}\0`);
  const out = new Uint8Array(label.length + serverChallenge.length + clientChallenge.length);
  out.set(label, 0);
  out.set(serverChallenge, label.length);
  out.set(clientChallenge, label.length + serverChallenge.length);
  return out;
}

export async function hmacSha256(keyBytes, message) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}
