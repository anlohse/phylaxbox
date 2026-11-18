# PhylaxBox file format — version 1

Status: **normative for format_version 1** (not yet released; may still change
until the first public build, after which changes require a new version).
Design rationale: [ADR 0001](../architecture/adr/0001-vault-format-v1.md).

Every encrypted file PhylaxBox writes — the vault (`*.phylaxbox`) and the
device-local config — uses this container. Any implementation (desktop C++,
Android, tools) that follows this document and passes the test vectors in
[`test-vectors/vault-v1.json`](test-vectors/vault-v1.json) can read and write
PhylaxBox files.

## Primitives

| Purpose                    | Algorithm                                              | libsodium API |
|----------------------------|--------------------------------------------------------|---------------|
| Password → KEK             | Argon2id v1.3, parallelism 1, 32-byte output           | `crypto_pwhash(..., crypto_pwhash_ALG_ARGON2ID13)` |
| Recovery key → KEK         | BLAKE2b-256 keyed hash                                 | `crypto_generichash` |
| Key wrap & payload         | XChaCha20-Poly1305 (IETF), 24-byte nonce, 16-byte tag  | `crypto_aead_xchacha20poly1305_ietf_*` |
| Compression                | zlib stream (RFC 1950)                                 | — |
| Randomness                 | OS CSPRNG                                              | `randombytes_buf` |

## Key hierarchy

```
password ──Argon2id(salt, t, m)──────────────▶ KEK₁ ─┐
recovery key ──BLAKE2b(key, context‖salt)────▶ KEK₂ ─┤ each wraps the same
                                                     ▼
                                     vault key (DEK, 32 random bytes)
                                                     │ XChaCha20-Poly1305
                                                     ▼
                                     payload (vault id, revision, content)
```

* The **vault key** (DEK) is random and never derived from a secret the user
  types. Each **key slot** stores the DEK wrapped under one KEK.
* Changing the master password replaces the password slot only. Adding or
  removing the recovery key changes only the recovery slot. Neither needs the
  other secret, and the payload is simply re-encrypted on the next save.
* A wrong password or recovery key is detected when the slot unwrap fails. If
  the unwrap succeeds but the payload does not authenticate, the file was
  corrupted or tampered with. Implementations must report these differently.

## Password encoding

UTF-8 after **Unicode NFC normalization** (the UI layer normalizes:
`String.prototype.normalize('NFC')`, `java.text.Normalizer`). Empty passwords
are rejected.

## Layout

All integers are unsigned little-endian. Offsets in bytes.

### Fixed header (40 bytes)

| Offset | Size | Field            | Value / meaning |
|-------:|-----:|------------------|-----------------|
| 0      | 8    | `magic`          | ASCII `PHYLAXBX` |
| 8      | 2    | `format_version` | `1` |
| 10     | 1    | `content_type`   | `1` = vault, `2` = device-local config |
| 11     | 1    | `aead_id`        | `1` = XChaCha20-Poly1305-IETF |
| 12     | 2    | `flags`          | `0` (readers MUST reject non-zero) |
| 14     | 1    | `slot_count`     | `1`..`4` |
| 15     | 1    | `reserved`       | `0` (readers MUST reject non-zero) |
| 16     | 24   | `payload_nonce`  | random, **new on every save** |

Bytes `[0, 12)` are the **stable prefix**: they never change during a file's life.

### Key slots (`slot_count` × 100 bytes, from offset 40)

| Offset | Size | Field             | Password slot (`1`)           | Recovery slot (`2`) |
|-------:|-----:|-------------------|-------------------------------|---------------------|
| 0      | 1    | `slot_type`       | `1`                           | `2` |
| 1      | 3    | `reserved`        | `0`                           | `0` |
| 4      | 4    | `kdf_opslimit`    | Argon2 iterations (t)         | `0` |
| 8      | 4    | `kdf_memlimit_kib`| Argon2 memory in KiB (m)      | `0` |
| 12     | 16   | `salt`            | random                        | random |
| 28     | 24   | `key_nonce`       | random, new on every re-wrap  | random, new on every re-wrap |
| 52     | 48   | `wrapped_key`     | DEK ciphertext ‖ 16-byte tag  | same |

At most one slot of each type. The header is bytes `[0, 40 + 100 × slot_count)`.

* Password KEK = `Argon2id(password, salt, t = kdf_opslimit, m = kdf_memlimit_kib × 1024 bytes, 32 bytes)`
* Recovery KEK = `BLAKE2b-256(key = recovery key (32 bytes), message = "PhylaxBox recovery slot v1" ‖ salt)` (ASCII context, no terminator)
* `wrapped_key = AEAD_Encrypt(key = KEK, nonce = key_nonce, ad = header[0..12) ‖ slot[0..52), msg = DEK)`

The slot's associated data excludes `slot_count` and the other slots, so a slot
can be added, replaced or removed without the secrets of the others.

### Payload (from the end of the header to the end of the file)

`payload = AEAD_Encrypt(key = DEK, nonce = payload_nonce, ad = whole header, msg = encoded_payload)`

Because the whole header is associated data, any change to it (KDF parameters,
slots, content type…) invalidates the payload; every save re-encrypts it.

Encoded payload (the AEAD plaintext):

| Offset | Size | Field             | Meaning |
|-------:|-----:|-------------------|---------|
| 0      | 16   | `vault_id`        | random at creation, constant for the vault's life |
| 16     | 8    | `revision`        | file revision, +1 on every save |
| 24     | 1    | `encoding`        | `0` = raw, `1` = zlib |
| 25     | …    | raw: `content`    | |
| 25     | 8    | zlib: `original_length` | decompressed length |
| 33     | …    | zlib: `stream`    | RFC 1950 zlib stream |

Compression information lives inside the encrypted payload, not in the clear
header, so only what is needed to unlock the file is exposed.

Readers MUST verify that the zlib stream inflates to exactly `original_length`
bytes and MUST refuse `original_length` greater than 64 MiB. Compressed bytes
differ between zlib implementations, so only decrypted content is compared
across platforms.

## Rollback protection

`vault_id` and `revision` are authenticated inside the payload. Every client
remembers, per `vault_id`, the highest `revision` it has seen (its local copy
records it). When a downloaded file has the same `vault_id` but a **lower**
revision, it is an older version restored by someone with access to the cloud
account — never apply it silently: warn the user and keep the newer copy.
After merging two versions, the next save must use a revision above both.

## Reader validation order

1. Length ≥ 40. Magic. `format_version == 1` (else report "unsupported version").
2. `content_type` is the one the caller expects; `aead_id == 1`; `flags == 0`; `reserved == 0`.
3. `1 ≤ slot_count ≤ 4`; length ≥ header + 25 + 16.
4. Each slot: known type, reserved bytes zero, at most one per type. Password
   slots: `1 ≤ t ≤ 16` and `8 ≤ m ≤ 1 048 576` KiB — checked **before** running
   Argon2 so a hostile file cannot exhaust memory or CPU. Recovery slots: t = m = 0.
5. Derive the KEK for the requested slot and unwrap the DEK (failure ⇒ wrong
   password / recovery key; no slot of that type ⇒ "no recovery key").
6. Decrypt the payload (failure ⇒ integrity error), decode it.

## Recovery key text

The recovery key is 32 random bytes shown to the user once. Text form:

1. `raw = key ‖ BLAKE2b-256(key)[0..2]` (unkeyed hash, first 2 bytes: typo check) — 34 bytes.
2. Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), most significant
   bit first, padding the final 3 bits with zeros — 55 characters.
3. Groups of 5 joined by `-`: `XXXXX-XXXXX-…` (11 groups).

Parsers ignore case, `-` and whitespace, read `O` as `0` and `I`/`L` as `1`,
and reject other characters, a wrong length, non-zero padding bits or a
checksum mismatch.

## Parameters for new files

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `kdf_opslimit` | 3 | |
| `kdf_memlimit_kib` | 65 536 (64 MiB) | Above OWASP's Argon2id floor (19 MiB, t=2) and workable on low-end Android. |

Parameters are stored per slot and can be raised on the next password entry
(re-derive, re-wrap) without a format change.

## Writing

* New `payload_nonce` on every save; new `salt` and `key_nonce` on every
  re-wrap. Never reuse a nonce with the same key.
* Write to a temporary file in the same directory, flush to disk, then rename
  over the old file.

## Vault content (schema 1)

The payload content of a `content_type = 1` file is UTF-8 JSON:

```json
{
  "schema": 1,
  "entries": [
    {
      "id": "6f9619ff-8b86-4d01-b42d-00c04fc964ff",
      "title": "Example",
      "username": "alice",
      "password": "hunter2",
      "urls": ["https://example.com"],
      "application": "",
      "notes": "",
      "tags": [],
      "favorite": false,
      "createdAt": "2026-11-17T12:00:00.000Z",
      "updatedAt": "2026-11-17T12:00:00.000Z",
      "revision": 1,
      "deviceId": "0b6e1c1a-3f5d-4a8e-9c2b-7d4e5f6a7b8c"
    }
  ],
  "tombstones": [
    { "id": "…", "deletedAt": "…", "revision": 2, "deviceId": "…" }
  ],
  "preferences": {}
}
```

* `id`, `deviceId`: lowercase canonical UUIDs (new ids are version 4).
* Timestamps: RFC 3339 UTC, `YYYY-MM-DDTHH:MM:SSZ` or with `.sss` milliseconds.
* `revision` (entry): integer ≥ 1, incremented on every change of the entry.
* Required per entry: `id`, `createdAt`, `updatedAt`, `revision`, `deviceId`.
  Other fields default to empty / `false`. Writers emit all fields.
* A deleted entry becomes a **tombstone**: its secrets are dropped, only what
  synchronization needs is kept. An id may not be both live and deleted.
* Tombstones are kept for **180 days** after `deletedAt`; writers drop older
  ones on save ([ADR 0002](../architecture/adr/0002-webview-cpp20-tombstones.md)).
  A device that stays offline longer than that may bring such entries back
  when it synchronizes.
* **Forward compatibility:** readers MUST preserve unknown fields (top-level
  and per entry/tombstone) and write them back unchanged. A `schema` greater
  than the reader's is refused ("written by a newer version").
* At most 100 000 entries and 100 000 tombstones.

The device-local config (`content_type = 2`) has its own JSON, versioned by
its `format` field.

## Test vectors

[`test-vectors/vault-v1.json`](test-vectors/vault-v1.json) contains vectors
built with fixed salts, nonces, keys, vault ids and recovery keys:
password only, password + recovery slot (non-ASCII password), device config,
and zlib. For `encoding: raw` the whole file is deterministic and
implementations must reproduce `file_hex` byte for byte; for `zlib` they
must only decrypt it. Recovery vectors also fix the key's text form.

Checked by:

* C++ core — `tests/crypto/vault_file_tests.cpp`
* Independent JS implementation (libsodium.js + Node zlib) — `tools/vault-reference/verify.mjs`

## Out of scope for v1

* Biometric / OS-keystore slots (a new `slot_type` when designed).
* Field-level encryption inside the content; passkeys (new fields under
  forward-compatibility rules, or a new schema).
