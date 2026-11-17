// Checks the JS reference implementation against docs/vault-format/test-vectors/vault-v1.json.
// Usage: npm install && npm test   (optionally: node verify.mjs <vectors.json>)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { deflateSync, inflateSync } from 'node:zlib';
import sodiumModule from 'libsodium-wrappers-sumo';
import {
  openVault, sealVault, deriveKek, recoveryKeyFromText, recoveryKeyToText, VaultError,
} from './vault.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = process.argv[2] ?? resolve(here, '../../docs/vault-format/test-vectors/vault-v1.json');

await sodiumModule.ready;
const sodium = sodiumModule;
const hex = (u8) => sodium.to_hex(u8);
const unhex = (s) => sodium.from_hex(s);
const inflate = (data, size) => new Uint8Array(inflateSync(data, { maxOutputLength: Math.max(size, 1) }));
const deflate = (data) => new Uint8Array(deflateSync(data, { level: 9 }));
const text = (u8) => new TextDecoder().decode(u8);

const doc = JSON.parse(readFileSync(vectorsPath, 'utf8'));
let failures = 0;
const check = (name, cond, detail) => {
  if (!cond) {
    failures++;
    console.error(`  FAIL ${name}${detail ? `: ${detail}` : ''}`);
  }
};
const expectError = (name, kind, fn) => {
  try {
    fn();
    check(name, false, 'no error thrown');
  } catch (e) {
    check(name, e instanceof VaultError && e.kind === kind, `${e.kind ?? ''} ${e.message}`);
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

  // 2. Decrypt the published file with the password.
  const opened = openVault(sodium, { password }, file, v.content_type, { inflate });
  check('vault key', hex(opened.vaultKey) === v.vault_key_hex);
  check('vault id', hex(opened.vaultId) === v.vault_id_hex);
  check('revision', opened.revision === BigInt(v.revision));
  check('plaintext', text(opened.content) === v.plaintext);

  // 3. Recovery key: text encoding and unlocking.
  let recovery;
  if (v.recovery) {
    const key = recoveryKeyFromText(sodium, v.recovery.key_text);
    check('recovery key text decode', hex(key) === v.recovery.key_hex);
    check('recovery key text encode', recoveryKeyToText(sodium, unhex(v.recovery.key_hex)) === v.recovery.key_text);
    const viaRecovery = openVault(sodium, { recoveryKey: key }, file, v.content_type, { inflate });
    check('recovery plaintext', text(viaRecovery.content) === v.plaintext);
    recovery = { key, salt: unhex(v.recovery.salt_hex), keyNonce: unhex(v.recovery.key_nonce_hex) };
  } else {
    expectError('no recovery slot', 'no-recovery-slot', () =>
      openVault(sodium, { recoveryKey: new Uint8Array(32) }, file, v.content_type, { inflate }));
  }

  // 4. Rebuild the file from the inputs alone (raw encoding is deterministic).
  const rebuilt = sealVault(sodium, {
    password,
    contentType: v.content_type,
    opslimit: v.kdf_opslimit,
    memlimitKib: v.kdf_memlimit_kib,
    salt: unhex(v.salt_hex),
    keyNonce: unhex(v.key_nonce_hex),
    vaultKey: unhex(v.vault_key_hex),
    vaultId: unhex(v.vault_id_hex),
    revision: v.revision,
    payloadNonce: unhex(v.payload_nonce_hex),
    recovery,
    content: new TextEncoder().encode(v.plaintext),
    compress: v.encoding === 'zlib',
    deflate,
  });
  check('wrapped key', hex(rebuilt.subarray(40 + 52, 40 + 100)) === v.wrapped_key_hex);
  if (v.recovery) {
    check('recovery wrapped key', hex(rebuilt.subarray(140 + 52, 140 + 100)) === v.recovery.wrapped_key_hex);
  }
  if (v.encoding === 'raw') {
    check('file bytes', hex(rebuilt) === v.file_hex);
  } else {
    const reopened = openVault(sodium, { password }, rebuilt, v.content_type, { inflate });
    check('zlib round trip', text(reopened.content) === v.plaintext);
  }

  // 5. Wrong password, tampering and a mistyped recovery key are reported as such.
  expectError('wrong password', 'wrong-password', () =>
    openVault(sodium, { password: password + 'x' }, file, v.content_type, { inflate }));
  const tampered = file.slice();
  tampered[tampered.length - 1] ^= 1;
  expectError('tampered payload', 'integrity', () =>
    openVault(sodium, { password }, tampered, v.content_type, { inflate }));
  if (v.recovery) {
    const typo = v.recovery.key_text.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
    expectError('mistyped recovery key', 'invalid-recovery-key', () => recoveryKeyFromText(sodium, typo));
  }
}

if (failures) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log(`all ${doc.vectors.length} vectors OK`);
