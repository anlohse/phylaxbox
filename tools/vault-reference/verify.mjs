// Checks the JS reference implementation against docs/vault-format/test-vectors/vault-v1.json.
// Usage: npm install && npm test   (optionally: node verify.mjs <vectors.json>)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { deflateSync, inflateSync } from 'node:zlib';
import sodiumModule from 'libsodium-wrappers-sumo';
import { openVault, sealVault, deriveKek, VaultError } from './vault.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = process.argv[2] ?? resolve(here, '../../docs/vault-format/test-vectors/vault-v1.json');

await sodiumModule.ready;
const sodium = sodiumModule;
const hex = (u8) => sodium.to_hex(u8);
const unhex = (s) => sodium.from_hex(s);
const inflate = (data, size) => new Uint8Array(inflateSync(data, { maxOutputLength: Math.max(size, 1) }));
const deflate = (data) => new Uint8Array(deflateSync(data, { level: 9 }));

const doc = JSON.parse(readFileSync(vectorsPath, 'utf8'));
let failures = 0;
const check = (name, cond, detail) => {
  if (!cond) {
    failures++;
    console.error(`  FAIL ${name}${detail ? `: ${detail}` : ''}`);
  }
};

for (const v of doc.vectors) {
  console.log(`vector ${v.name}`);
  const password = new TextDecoder('utf-8', { fatal: true }).decode(unhex(v.password_utf8_hex));
  const file = unhex(v.file_hex);

  // 1. KEK derivation (Argon2id) matches.
  const kek = deriveKek(sodium, unhex(v.password_utf8_hex), unhex(v.salt_hex), v.kdf_opslimit,
                        v.kdf_memlimit_kib);
  check('kek', hex(kek) === v.kek_hex);

  // 2. Decrypt the published file.
  const opened = openVault(sodium, password, file, v.content_type, { inflate });
  check('vault key', hex(opened.vaultKey) === v.vault_key_hex);
  check('plaintext', new TextDecoder().decode(opened.content) === v.plaintext);

  // 3. Rebuild the file from the inputs alone (raw encoding is deterministic).
  const rebuilt = sealVault(sodium, {
    password,
    contentType: v.content_type,
    opslimit: v.kdf_opslimit,
    memlimitKib: v.kdf_memlimit_kib,
    salt: unhex(v.salt_hex),
    keyNonce: unhex(v.key_nonce_hex),
    vaultKey: unhex(v.vault_key_hex),
    payloadNonce: unhex(v.payload_nonce_hex),
    content: new TextEncoder().encode(v.plaintext),
    compress: v.encoding === 'zlib',
    deflate,
  });
  check('wrapped key', hex(rebuilt.subarray(64, 112)) === v.wrapped_key_hex);
  if (v.encoding === 'raw') {
    check('file bytes', hex(rebuilt) === v.file_hex);
  } else {
    const reopened = openVault(sodium, password, rebuilt, v.content_type, { inflate });
    check('zlib round trip', new TextDecoder().decode(reopened.content) === v.plaintext);
  }

  // 4. Wrong password is reported as such.
  try {
    openVault(sodium, password + 'x', file, v.content_type, { inflate });
    check('wrong password rejected', false);
  } catch (e) {
    check('wrong password rejected', e instanceof VaultError && e.kind === 'wrong-password', e.message);
  }
}

if (failures) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log(`all ${doc.vectors.length} vectors OK`);
