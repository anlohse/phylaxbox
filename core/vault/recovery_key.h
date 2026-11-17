#ifndef PB_RECOVERY_KEY_H_
#define PB_RECOVERY_KEY_H_

#include "crypto/secure_bytes.h"

#include <string>
#include <string_view>

namespace pb {

// High-entropy recovery key (spec §5.1): 32 random bytes, shown to the user
// once as text. Text form (docs/vault-format/README.md, "Recovery key text"):
// Crockford base32 of key || 2-byte BLAKE2b checksum, 55 characters in
// 11 groups of 5 separated by '-'. Parsing ignores case, spaces and dashes,
// accepts I/L for 1 and O for 0, and rejects mistyped keys via the checksum.
class recovery_key {
public:
    static constexpr std::size_t BYTES = 32;

    static recovery_key generate();

    // Throws pbexception(INVALID_RECOVERY_KEY) on bad characters, length or checksum.
    static recovery_key parse(std::string_view text);

    // Builds a key from raw bytes (test vectors).
    static recovery_key from_bytes(byte_view bytes);

    std::string to_text() const;
    byte_view bytes() const { return m_key.view(); }

private:
    recovery_key() = default;
    secure_bytes m_key;
};

} // namespace pb

#endif // PB_RECOVERY_KEY_H_
