// The extension's half of the authentication must agree with the app's
// (tests/unit/browser_protocol_tests.cpp, BrowserAuth.CrossImplementationVector).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { authMessage, equalBytes, fromBase64, hmacSha256, toBase64 } from '../src/auth.js';

const counting = (start, n) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const hex = (bytes) => Buffer.from(bytes).toString('hex');

test('HMAC proofs match the desktop app', async () => {
  const key = counting(0, 32);
  const server = counting(0x40, 32);
  const client = counting(0x80, 32);
  assert.equal(hex(await hmacSha256(key, authMessage('client', server, client))),
    '96ca53dafe237e371c73e5ede1cb5da6f0c2092194ab00c17ea15086ba0f8aad');
  assert.equal(hex(await hmacSha256(key, authMessage('server', server, client))),
    'cb3216551e759e71382e261e2a1e6346fb89852ebc37fbda362526fff6486d19');
});

test('base64 round trip and comparison', () => {
  const bytes = counting(250, 40);
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  assert.equal(equalBytes(bytes, fromBase64(toBase64(bytes))), true);
  assert.equal(equalBytes(bytes, counting(0, 40)), false);
  assert.equal(equalBytes(bytes, bytes.subarray(1)), false);
});

test('the Chrome extension id matches its public key', () => {
  const ids = JSON.parse(readFileSync(new URL('../extension-ids.json', import.meta.url), 'utf8'));
  const digest = createHash('sha256').update(Buffer.from(ids.chrome.key, 'base64')).digest('hex').slice(0, 32);
  const id = [...digest].map((h) => String.fromCharCode(97 + parseInt(h, 16))).join('');
  assert.ok(ids.chrome.ids.includes(id), `key gives ${id}`);
});
