#ifndef PB_PASSWORD_GENERATOR_H_
#define PB_PASSWORD_GENERATOR_H_

#include "crypto/secure_allocator.h"

#include <cstddef>
#include <string>

namespace pb {

struct password_options {
    static constexpr std::size_t MIN_LENGTH = 8;
    static constexpr std::size_t MAX_LENGTH = 128;

    std::size_t length = 20;
    bool lowercase = true;
    bool uppercase = true;
    bool digits = true;
    bool symbols = true;
    bool avoid_ambiguous = false; // drops 0 O o 1 l I | ` ' "
};

// Random password from the OS CSPRNG (libsodium randombytes_uniform, no
// modulo bias), with at least one character of every selected class.
// Throws std::invalid_argument for a length out of range or no class selected.
secure_string generate_password(const password_options& options);

// The characters a class contributes under `options` (exposed for tests).
std::string password_alphabet(const password_options& options);

} // namespace pb

#endif // PB_PASSWORD_GENERATOR_H_
