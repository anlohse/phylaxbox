// Reference implementation of the PhylaxBox container v1 in JavaScript.
// Normative spec: docs/vault-format/README.md. Written independently from the C++
// core so the two can check each other; intended to seed the browser extension.
//
// `sodium` is a ready libsodium-wrappers-sumo instance (crypto_pwhash needs
// the sumo build). Compression is injected so this file runs in Node and in
// browsers (CompressionStream('deflate') produces RFC 1950 zlib streams).

export const HEADER_SIZE = 136;
export const KEY_AD_SIZE = 40;
export const MAX_CONTENT_SIZE = 64 * 1024 * 1024;
export const ContentType = Object.freeze({ VAULT: 1, LOCAL_CONFIG: 2 });

const MAGIC = new TextEncoder().encode('PHYLAXBX');
const TAG = 16;

export class VaultError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind; // 'format' | 'unsupported-version' | 'content-type' | 'wrong-password' | 'integrity'
  }
}

export function encodePassword(password) {
  if (!password) throw new VaultError('format', 'password must not be empty');
  return new TextEncoder().encode(password.normalize('NFC'));
}

export function parseHeader(file, expectedType) {
  if (file.length < HEADER_SIZE + TAG + 1) throw new VaultError('format', 'file too short');
  for (let i = 0; i < MAGIC.length; i++) {
    if (file[i] !== MAGIC[i]) throw new VaultError('format', 'not a PhylaxBox file');
  }
  const dv = new DataView(file.buffer, file.byteOffset, HEADER_SIZE);
  const version = dv.getUint16(8, true);
  if (version !== 1) throw new VaultError('unsupported-version', `format version ${version}`);
  if (dv.getUint16(10, true) !== 0 || dv.getUint16(14, true) !== 0) {
    throw new VaultError('format', 'reserved header fields are set');
  }
  if (file[12] !== 1) throw new VaultError('format', 'unknown KDF');
  if (file[13] !== expectedType) throw new VaultError('content-type', 'unexpected content type');
  const opslimit = dv.getUint32(16, true);
  const memlimitKib = dv.getUint32(20, true);
  if (opslimit < 1 || opslimit > 16 || memlimitKib < 8 || memlimitKib > 1024 * 1024) {
    throw new VaultError('format', 'KDF parameters out of range');
  }
  return {
    contentType: file[13],
    opslimit,
    memlimitKib,
    salt: file.slice(24, 40),
    keyNonce: file.slice(40, 64),
    wrappedKey: file.slice(64, 112),
    payloadNonce: file.slice(112, 136),
  };
}

export function serializeHeader(h) {
  const out = new Uint8Array(HEADER_SIZE);
  const dv = new DataView(out.buffer);
  out.set(MAGIC, 0);
  dv.setUint16(8, 1, true);
  dv.setUint16(10, 0, true);
  out[12] = 1;
  out[13] = h.contentType;
  dv.setUint16(14, 0, true);
  dv.setUint32(16, h.opslimit, true);
  dv.setUint32(20, h.memlimitKib, true);
  out.set(h.salt, 24);
  out.set(h.keyNonce, 40);
  out.set(h.wrappedKey, 64);
  out.set(h.payloadNonce, 112);
  return out;
}

export function deriveKek(sodium, passwordBytes, salt, opslimit, memlimitKib) {
  return sodium.crypto_pwhash(32, passwordBytes, salt, opslimit, memlimitKib * 1024,
                              sodium.crypto_pwhash_ALG_ARGON2ID13);
}

function aeadDecrypt(sodium, key, nonce, ciphertext, ad) {
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key);
  } catch {
    return null;
  }
}

/** Returns { vaultKey, header, content }. Throws VaultError. */
export function openVault(sodium, password, file, expectedType, { inflate }) {
  const header = parseHeader(file, expectedType);
  const ad = file.subarray(0, HEADER_SIZE);
  const kek = deriveKek(sodium, encodePassword(password), header.salt, header.opslimit,
                        header.memlimitKib);
  const vaultKey = aeadDecrypt(sodium, kek, header.keyNonce, header.wrappedKey,
                               ad.subarray(0, KEY_AD_SIZE));
  sodium.memzero(kek);
  if (!vaultKey || vaultKey.length !== 32) throw new VaultError('wrong-password', 'wrong password');

  const encoded = aeadDecrypt(sodium, vaultKey, header.payloadNonce, file.subarray(HEADER_SIZE), ad);
  if (!encoded) throw new VaultError('integrity', 'payload failed authentication');
  return { vaultKey, header, content: decodeContent(encoded, inflate) };
}

export function decodeContent(encoded, inflate) {
  if (encoded.length < 1) throw new VaultError('format', 'empty payload');
  if (encoded[0] === 0) return encoded.slice(1);
  if (encoded[0] === 1) {
    if (encoded.length < 9) throw new VaultError('format', 'truncated compressed payload');
    const original = new DataView(encoded.buffer, encoded.byteOffset + 1, 8).getBigUint64(0, true);
    if (original > BigInt(MAX_CONTENT_SIZE)) throw new VaultError('format', 'content too large');
    const out = inflate(encoded.subarray(9), Number(original));
    if (out.length !== Number(original)) throw new VaultError('format', 'wrong decompressed length');
    return out;
  }
  throw new VaultError('format', `unknown payload encoding ${encoded[0]}`);
}

export function encodeContent(content, compress, deflate) {
  if (!compress) {
    const out = new Uint8Array(1 + content.length);
    out.set(content, 1);
    return out;
  }
  const stream = deflate(content);
  const out = new Uint8Array(9 + stream.length);
  out[0] = 1;
  new DataView(out.buffer).setBigUint64(1, BigInt(content.length), true);
  out.set(stream, 9);
  return out;
}

/**
 * Builds a complete file. `salt`, `keyNonce`, `payloadNonce` and `vaultKey`
 * must be fresh random values except when reproducing test vectors.
 */
export function sealVault(sodium, { password, contentType, opslimit, memlimitKib, salt, keyNonce,
                                    vaultKey, payloadNonce, content, compress, deflate }) {
  const header = { contentType, opslimit, memlimitKib, salt, keyNonce,
                   wrappedKey: new Uint8Array(48), payloadNonce };
  const keyAd = serializeHeader(header).subarray(0, KEY_AD_SIZE);
  const kek = deriveKek(sodium, encodePassword(password), salt, opslimit, memlimitKib);
  header.wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(vaultKey, keyAd, null,
                                                                        keyNonce, kek);
  sodium.memzero(kek);
  const ad = serializeHeader(header);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    encodeContent(content, compress, deflate), ad, null, payloadNonce, vaultKey);
  const file = new Uint8Array(HEADER_SIZE + ciphertext.length);
  file.set(ad, 0);
  file.set(ciphertext, HEADER_SIZE);
  return file;
}
