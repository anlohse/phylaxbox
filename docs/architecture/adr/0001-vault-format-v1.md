# ADR 0001 — Vault file format v1

Status: accepted · 2026-11-17

## Context

The specification (§4, §5, §6.6, §12.1) asks for a portable, versioned vault
file with envelope encryption (KEK + DEK), an optional high-entropy recovery
key, minimal unencrypted metadata, protection against tampering and rollback,
and a JSON content model that can grow (passkeys, §11) without a redesign.
Desktop C++, Android and test tools must all produce identical files.

## Decisions

1. **Key slots.** The header holds 1–4 fixed-size slots, each wrapping the
   same random DEK: a password slot (Argon2id) and an optional recovery slot.
   Each slot's associated data is the stable header prefix plus the slot's own
   parameters, *excluding* the slot count, so the recovery key can be added or
   replaced while unlocked with the password alone.

2. **Recovery stays inside the vault (spec §5.2, option A).** The recovery key
   unwraps a slot in the vault header instead of a separate recovery file
   holding the wrapped DEK. A 256-bit random key cannot be brute-forced, so the
   extra slot does not weaken the file, and recovery keeps working if the DEK
   is rotated (a separate file would silently go stale). The "recovery file"
   becomes a printable kit containing the key text. The recovery KEK uses
   keyed BLAKE2b with a per-slot salt and a context string; Argon2 would add
   nothing for a uniformly random key.

3. **Recovery key text** is Crockford base32 with a 16-bit checksum, in groups
   of five, tolerant of case and of O/0, I/L/1 confusion, so typos are caught
   before trying to unlock.

4. **Compression identifier inside the payload**, not in the clear header
   (deviation from spec §4.4's list, consistent with its "only the metadata
   required to open the vault stays unencrypted"). zlib only in v1: it is
   available natively on every target (Android `java.util.zip`, browsers'
   `DecompressionStream`), and Zstandard brings little for small JSON. A new
   `encoding` value can add it later without a format change.

5. **AEAD identifier** in the header (`aead_id = 1`) so a future algorithm
   change is explicit rather than implied by the version.

6. **Rollback protection** (spec §12.1): a random `vault_id` and a monotonic
   `revision` are authenticated inside the payload. Clients remember the
   highest revision per vault and refuse to silently apply an older one.
   `reload()` lets an unlocked client read another version of the same vault
   with the DEK in memory — including after a password change on another
   device — and reports its revision for this check.

7. **Content schema 1**: JSON with stable UUIDs, per-entry revisions and
   device ids (input for the three-way merge, spec §6.6), and **tombstones**
   for deletions instead of a `deletedAt` field on the entry, so deleted
   passwords are actually removed from the file. Unknown fields are preserved
   on save (forward compatibility); a newer `schema` is refused.

8. **File extension** `.phylaxbox` for vaults (spec §4.1).

## Consequences

* The spec's §4.4 header list and §5.2 recovery-file wording should be read
  through decisions 2 and 4.
* Tombstone retention (how long before purging) is still to be decided with
  the synchronization design.
* Secrets in the parsed JSON model live in ordinary `std::string`s; keeping
  them in secure memory is left to the vault session design (spec §12.2).
