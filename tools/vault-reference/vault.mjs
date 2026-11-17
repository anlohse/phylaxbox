// Reference implementation of the PhylaxBox container v1 in JavaScript.
// Normative spec: docs/vault-format/README.md. Written independently from the
// C++ core so the two can check each other.
//
// `sodium` is a ready libsodium-wrappers-sumo instance (crypto_pwhash needs
// the sumo build). Compression is injected so this file runs in Node and in
// browsers (CompressionStream('deflate') produces RFC 1950 zlib streams).

export const FIXED_SIZE = 40;
export const SLOT_SIZE = 100;
export const SLOT_AD_SIZE = 52;
export const STABLE_PREFIX = 12;
export const MAX_SLOTS = 4;
export const MAX_CONTENT_SIZE = 64 * 1024 * 1024;
export const ContentType = Object.freeze({ VAULT: 1, LOCAL_CONFIG: 2 });
export const SlotType = Object.freeze({ PASSWORD: 1, RECOVERY_KEY: 2 });

const MAGIC = new TextEncoder().encode('PHYLAXBX');
const RECOVERY_CONTEXT = new TextEncoder().encode('PhylaxBox recovery slot v1');
const TAG = 16;
const PAYLOAD_PREFIX = 25; // vault_id(16) + revision(8) + encoding(1)

export class VaultError extends Error {
  constructor(kind, message) {
    super(message);
    // 'format' | 'unsupported-version' | 'content-type' | 'wrong-password' |
    // 'integrity' | 'no-recovery-slot' | 'invalid-recovery-key'
    this.kind = kind;
  }
}

export function encodePassword(password) {
  if (!password) throw new VaultError('format', 'password must not be empty');
  return new TextEncoder().encode(password.normalize('NFC'));
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function stablePrefix(contentType) {
  const p = new Uint8Array(STABLE_PREFIX);
  p.set(MAGIC, 0);
  new DataView(p.buffer).setUint16(8, 1, true);
  p[10] = contentType;
  p[11] = 1; // XChaCha20-Poly1305
  return p;
}

function slotBytes(slot) {
  const s = new Uint8Array(SLOT_SIZE);
  const dv = new DataView(s.buffer);
  s[0] = slot.type;
  dv.setUint32(4, slot.opslimit ?? 0, true);
  dv.setUint32(8, slot.memlimitKib ?? 0, true);
  s.set(slot.salt, 12);
  s.set(slot.keyNonce, 28);
  if (slot.wrappedKey) s.set(slot.wrappedKey, 52);
  return s;
}

export function slotAd(contentType, slot) {
  const ad = new Uint8Array(STABLE_PREFIX + SLOT_AD_SIZE);
  ad.set(stablePrefix(contentType), 0);
  ad.set(slotBytes(slot).subarray(0, SLOT_AD_SIZE), STABLE_PREFIX);
  return ad;
}

export function serializeHeader(h) {
  const out = new Uint8Array(FIXED_SIZE + h.slots.length * SLOT_SIZE);
  out.set(stablePrefix(h.contentType), 0);
  out[14] = h.slots.length;
  out.set(h.payloadNonce, 16);
  h.slots.forEach((s, i) => out.set(slotBytes(s), FIXED_SIZE + i * SLOT_SIZE));
  return out;
}

export function parseHeader(file, expectedType) {
  const fail = (msg, kind = 'format') => { throw new VaultError(kind, msg); };
  if (file.length < FIXED_SIZE) fail('file too short');
  for (let i = 0; i < MAGIC.length; i++) if (file[i] !== MAGIC[i]) fail('not a PhylaxBox file');
  const dv = new DataView(file.buffer, file.byteOffset, file.length);
  const version = dv.getUint16(8, true);
  if (version !== 1) fail(`format version ${version}`, 'unsupported-version');
  if (file[10] !== expectedType) fail('unexpected content type', 'content-type');
  if (file[11] !== 1) fail('unknown AEAD');
  if (dv.getUint16(12, true) !== 0 || file[15] !== 0) fail('reserved header fields are set');
  const count = file[14];
  if (count < 1 || count > MAX_SLOTS) fail('invalid key slot count');
  const size = FIXED_SIZE + count * SLOT_SIZE;
  if (file.length < size + PAYLOAD_PREFIX + TAG) fail('file too short');

  const slots = [];
  for (let i = 0; i < count; i++) {
    const o = FIXED_SIZE + i * SLOT_SIZE;
    if (file[o + 1] || file[o + 2] || file[o + 3]) fail('reserved key slot fields are set');
    const slot = {
      type: file[o],
      opslimit: dv.getUint32(o + 4, true),
      memlimitKib: dv.getUint32(o + 8, true),
      salt: file.slice(o + 12, o + 28),
      keyNonce: file.slice(o + 28, o + 52),
      wrappedKey: file.slice(o + 52, o + 100),
    };
    if (slot.type === SlotType.PASSWORD) {
      if (slot.opslimit < 1 || slot.opslimit > 16 || slot.memlimitKib < 8 ||
          slot.memlimitKib > 1024 * 1024) fail('KDF parameters out of range');
    } else if (slot.type === SlotType.RECOVERY_KEY) {
      if (slot.opslimit !== 0 || slot.memlimitKib !== 0) fail('recovery slot has KDF parameters');
    } else {
      fail('unknown key slot type');
    }
    if (slots.some((s) => s.type === slot.type)) fail('duplicate key slot type');
    slots.push(slot);
  }
  return { contentType: expectedType, payloadNonce: file.slice(16, 40), slots, size };
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

export function deriveKek(sodium, passwordBytes, salt, opslimit, memlimitKib) {
  return sodium.crypto_pwhash(32, passwordBytes, salt, opslimit, memlimitKib * 1024,
                              sodium.crypto_pwhash_ALG_ARGON2ID13);
}

export function recoveryKek(sodium, recoveryKeyBytes, salt) {
  const msg = new Uint8Array(RECOVERY_CONTEXT.length + salt.length);
  msg.set(RECOVERY_CONTEXT, 0);
  msg.set(salt, RECOVERY_CONTEXT.length);
  return sodium.crypto_generichash(32, msg, recoveryKeyBytes);
}

// ---------------------------------------------------------------------------
// Recovery key text: Crockford base32 of key || BLAKE2b(key)[0..2], 11 x 5 chars
// ---------------------------------------------------------------------------

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function recoveryKeyToText(sodium, key) {
  const raw = new Uint8Array(34);
  raw.set(key, 0);
  raw.set(sodium.crypto_generichash(32, key).subarray(0, 2), 32);
  let bits = '';
  for (const b of raw) bits += b.toString(2).padStart(8, '0');
  bits = bits.padEnd(55 * 5, '0');
  let out = '';
  for (let i = 0; i < 55; i++) {
    if (i > 0 && i % 5 === 0) out += '-';
    out += CROCKFORD[parseInt(bits.slice(i * 5, i * 5 + 5), 2)];
  }
  return out;
}

export function recoveryKeyFromText(sodium, text) {
  const fail = (msg) => { throw new VaultError('invalid-recovery-key', msg); };
  let bits = '';
  for (const ch of text.toUpperCase().replace(/[-\s]/g, '')) {
    const c = ch === 'O' ? '0' : (ch === 'I' || ch === 'L') ? '1' : ch;
    const v = CROCKFORD.indexOf(c);
    if (v < 0) fail('invalid character');
    bits += v.toString(2).padStart(5, '0');
  }
  if (bits.length !== 55 * 5) fail('wrong length');
  if (/1/.test(bits.slice(272))) fail('mistyped');
  const raw = new Uint8Array(34);
  for (let i = 0; i < 34; i++) raw[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const key = raw.slice(0, 32);
  const check = sodium.crypto_generichash(32, key).subarray(0, 2);
  if (check[0] !== raw[32] || check[1] !== raw[33]) fail('mistyped');
  return key;
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

export function decodePayload(encoded, inflate) {
  if (encoded.length < PAYLOAD_PREFIX) throw new VaultError('format', 'truncated payload');
  const dv = new DataView(encoded.buffer, encoded.byteOffset, encoded.length);
  const vaultId = encoded.slice(0, 16);
  const revision = dv.getBigUint64(16, true);
  const encoding = encoded[24];
  const body = encoded.subarray(PAYLOAD_PREFIX);
  if (encoding === 0) return { vaultId, revision, content: body.slice() };
  if (encoding === 1) {
    if (body.length < 8) throw new VaultError('format', 'truncated compressed payload');
    const original = new DataView(body.buffer, body.byteOffset, 8).getBigUint64(0, true);
    if (original > BigInt(MAX_CONTENT_SIZE)) throw new VaultError('format', 'content too large');
    const content = inflate(body.subarray(8), Number(original));
    if (content.length !== Number(original)) throw new VaultError('format', 'wrong decompressed length');
    return { vaultId, revision, content };
  }
  throw new VaultError('format', `unknown payload encoding ${encoding}`);
}

export function encodePayload(vaultId, revision, content, compress, deflate) {
  const body = compress ? deflate(content) : content;
  const out = new Uint8Array(PAYLOAD_PREFIX + (compress ? 8 : 0) + body.length);
  const dv = new DataView(out.buffer);
  out.set(vaultId, 0);
  dv.setBigUint64(16, BigInt(revision), true);
  out[24] = compress ? 1 : 0;
  if (compress) {
    dv.setBigUint64(PAYLOAD_PREFIX, BigInt(content.length), true);
    out.set(body, PAYLOAD_PREFIX + 8);
  } else {
    out.set(body, PAYLOAD_PREFIX);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Open / seal
// ---------------------------------------------------------------------------

function aeadDecrypt(sodium, key, nonce, ciphertext, ad) {
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key);
  } catch {
    return null;
  }
}

/**
 * Opens a file. `unlock` is { password } or { recoveryKey: Uint8Array(32) }.
 * Returns { vaultKey, header, vaultId, revision, content }. Throws VaultError.
 */
export function openVault(sodium, unlock, file, expectedType, { inflate }) {
  const header = parseHeader(file, expectedType);
  const wantType = unlock.recoveryKey ? SlotType.RECOVERY_KEY : SlotType.PASSWORD;
  const slot = header.slots.find((s) => s.type === wantType);
  if (!slot) {
    throw wantType === SlotType.RECOVERY_KEY
      ? new VaultError('no-recovery-slot', 'vault has no recovery key')
      : new VaultError('format', 'vault has no password slot');
  }
  const kek = wantType === SlotType.PASSWORD
    ? deriveKek(sodium, encodePassword(unlock.password), slot.salt, slot.opslimit, slot.memlimitKib)
    : recoveryKek(sodium, unlock.recoveryKey, slot.salt);
  const vaultKey = aeadDecrypt(sodium, kek, slot.keyNonce, slot.wrappedKey,
                               slotAd(expectedType, slot));
  sodium.memzero(kek);
  if (!vaultKey || vaultKey.length !== 32) {
    throw new VaultError('wrong-password', unlock.recoveryKey ? 'wrong recovery key' : 'wrong password');
  }
  const encoded = aeadDecrypt(sodium, vaultKey, header.payloadNonce,
                              file.subarray(header.size), file.subarray(0, header.size));
  if (!encoded) throw new VaultError('integrity', 'payload failed authentication');
  return { vaultKey, header, ...decodePayload(encoded, inflate) };
}

function wrapSlot(sodium, contentType, slot, kek, vaultKey) {
  slot.wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    vaultKey, slotAd(contentType, slot), null, slot.keyNonce, kek);
  sodium.memzero(kek);
  return slot;
}

/**
 * Builds a complete file. All salts, nonces, ids and keys must be fresh random
 * values except when reproducing test vectors.
 */
export function sealVault(sodium, p) {
  const slots = [wrapSlot(sodium, p.contentType, {
    type: SlotType.PASSWORD, opslimit: p.opslimit, memlimitKib: p.memlimitKib,
    salt: p.salt, keyNonce: p.keyNonce,
  }, deriveKek(sodium, encodePassword(p.password), p.salt, p.opslimit, p.memlimitKib), p.vaultKey)];
  if (p.recovery) {
    slots.push(wrapSlot(sodium, p.contentType, {
      type: SlotType.RECOVERY_KEY, salt: p.recovery.salt, keyNonce: p.recovery.keyNonce,
    }, recoveryKek(sodium, p.recovery.key, p.recovery.salt), p.vaultKey));
  }
  const ad = serializeHeader({ contentType: p.contentType, payloadNonce: p.payloadNonce, slots });
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    encodePayload(p.vaultId, p.revision, p.content, p.compress, p.deflate), ad, null,
    p.payloadNonce, p.vaultKey);
  const file = new Uint8Array(ad.length + ciphertext.length);
  file.set(ad, 0);
  file.set(ciphertext, ad.length);
  return file;
}
