# PhylaxBox container format — version 1

Status: **draft, normative for format_version 1.**

Every encrypted file PhylaxBox writes (the synced vault and the device-local
config) uses this container. Any implementation (desktop C++, browser
extension, Android) that follows this document and passes the test vectors in
[`test-vectors/vault-v1.json`](test-vectors/vault-v1.json) can read and write
PhylaxBox files.

## Primitives

| Purpose            | Algorithm                                        | libsodium API |
|--------------------|--------------------------------------------------|---------------|
| Password → KEK     | Argon2id v1.3, parallelism 1, 32-byte output     | `crypto_pwhash(..., crypto_pwhash_ALG_ARGON2ID13)` |
| Key wrap & payload | XChaCha20-Poly1305 (IETF), 24-byte nonce, 16-byte tag | `crypto_aead_xchacha20poly1305_ietf_*` |
| Compression        | zlib stream (RFC 1950)                           | — |
| Randomness         | OS CSPRNG                                        | `randombytes_buf` |

## Key hierarchy

```
password ──Argon2id(salt, ops, mem)──▶ KEK (32 B)
                                        │ XChaCha20-Poly1305 (key_nonce, AD = header[0..40))
                                        ▼
                         wrapped_key ◀── vault key (32 B, random, fixed for the file's life)
                                        │ XChaCha20-Poly1305 (payload_nonce, AD = header[0..136))
                                        ▼
                                    payload ciphertext
```

* The **vault key** is random and never derived from the password. Changing the
  master password only re-derives the KEK and re-wraps the vault key (new salt,
  new `key_nonce`). Future unlock methods (e.g. Android biometrics) add their own
  wrap of the same vault key.
* A wrong password is detected when the key unwrap fails. If the unwrap succeeds
  but the payload does not authenticate, the file was corrupted or tampered with.
  Implementations should report these two cases differently.

## Password encoding

The password is encoded as UTF-8 after **Unicode NFC normalization**. The UI
layer is responsible for normalizing (`String.prototype.normalize('NFC')` in
JS, `java.text.Normalizer` on Android). An empty password is rejected.

## Layout

All integers are unsigned little-endian. Offsets in bytes.

| Offset | Size | Field             | Value / meaning |
|-------:|-----:|-------------------|-----------------|
| 0      | 8    | `magic`           | ASCII `PHYLAXBX` |
| 8      | 2    | `format_version`  | `1` |
| 10     | 2    | `flags`           | `0` (reserved; readers MUST reject non-zero) |
| 12     | 1    | `kdf_id`          | `1` = Argon2id v1.3 |
| 13     | 1    | `content_type`    | `1` = synced vault, `2` = device-local config |
| 14     | 2    | `reserved`        | `0` (readers MUST reject non-zero) |
| 16     | 4    | `kdf_opslimit`    | Argon2 iterations (t) |
| 20     | 4    | `kdf_memlimit_kib`| Argon2 memory in KiB (m); bytes = value × 1024 |
| 24     | 16   | `kdf_salt`        | random |
| 40     | 24   | `key_nonce`       | random, new on every re-wrap |
| 64     | 48   | `wrapped_key`     | 32-byte vault key ciphertext ‖ 16-byte tag |
| 112    | 24   | `payload_nonce`   | random, **new on every save** |
| 136    | ≥17  | `payload`         | ciphertext ‖ 16-byte tag |

The header is bytes `[0, 136)`.

* `wrapped_key = AEAD_Encrypt(key = KEK, nonce = key_nonce, ad = header[0..40), msg = vault_key)`
* `payload    = AEAD_Encrypt(key = vault_key, nonce = payload_nonce, ad = header[0..136), msg = encoded_payload)`

Because the whole header is the payload's associated data, any change to a
header field (KDF parameters, salt, content type…) invalidates the payload.
After a password change the payload must be re-encrypted.

### Encoded payload (plaintext inside the AEAD)

| Offset | Size | Field             | Meaning |
|-------:|-----:|-------------------|---------|
| 0      | 1    | `encoding`        | `0` = raw, `1` = zlib |
| 1      | …    | raw: `data`       | the content bytes |
| 1      | 8    | zlib: `original_length` | length of the decompressed content |
| 9      | …    | zlib: `stream`    | RFC 1950 zlib stream |

Readers MUST verify that the zlib stream inflates to exactly
`original_length` bytes and MUST refuse `original_length` greater than
64 MiB (decompression-bomb guard). Compression output differs between zlib
implementations, so only the decrypted content — never the compressed
bytes — is compared across platforms.

## Reader validation order

1. Length ≥ 136 + 16 + 1. Magic matches. `format_version == 1` (otherwise report
   "unsupported version", not "corrupted").
2. `flags == 0`, `reserved == 0`, `kdf_id == 1`, `content_type` is the one the
   caller expects.
3. KDF limits — reject before running Argon2 so a hostile file cannot exhaust
   memory or CPU: `1 ≤ opslimit ≤ 16`, `8 ≤ memlimit_kib ≤ 1 048 576` (1 GiB).
4. Derive KEK, unwrap vault key (failure ⇒ wrong password).
5. Decrypt payload (failure ⇒ integrity error), decode `encoding`.

## Parameters for new files

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `opslimit` | 3 | |
| `memlimit_kib` | 65 536 (64 MiB) | Above OWASP's Argon2id minimum (19 MiB, t=2) and still workable in a browser WASM build and on low-end Android. |

Parameters are stored per file, so they can be raised later without a format
change: on the next password entry, re-derive with new parameters and re-wrap.

## Writing

* Draw a fresh `payload_nonce` for every save; never reuse one with the same
  vault key. (XChaCha20's 192-bit nonces make random nonces safe.)
* Write to a temporary file in the same directory, flush to disk, then rename
  over the old file.

## Test vectors

[`test-vectors/vault-v1.json`](test-vectors/vault-v1.json) contains vectors
built with fixed salt, nonces and vault key. For `encoding: raw` vectors the
whole file is deterministic and implementations must reproduce `file_hex`
byte-for-byte. For `encoding: zlib` vectors implementations must only decrypt
`file_hex` to `plaintext`.

Two implementations are checked against them:

* C++ core — `tests/crypto/vault_file_tests.cpp`
* Independent JS reference (libsodium.js + Node zlib) — `tools/vault-reference/verify.mjs`

## Out of scope for v1

* Structure of the vault content (entries, folders). It is a JSON document
  versioned on its own and specified separately.
* Multiple key slots (biometrics, recovery key). They will use a new
  `format_version` or a flag bit.
* Merging edits from different devices (handled at the content level).
