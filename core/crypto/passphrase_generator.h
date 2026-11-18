#ifndef PB_PASSPHRASE_GENERATOR_H_
#define PB_PASSPHRASE_GENERATOR_H_

#include "crypto/secure_allocator.h"

#include <cstddef>
#include <string>
#include <string_view>

namespace pb {

// Diceware-style passphrases from the EFF Long Wordlist (7 776 words,
// ~12.9 bits each; see core/crypto/data/README.md).
struct passphrase_options {
    static constexpr std::size_t MIN_WORDS = 4;
    static constexpr std::size_t MAX_WORDS = 20;

    std::size_t words = 6;
    std::string separator = "-"; // up to 3 characters, no letters
    bool capitalize = false;     // "Word" instead of "word"
    bool include_number = false; // appends one random digit to one random word
};

// Uses the OS CSPRNG. Throws std::invalid_argument for out-of-range options.
secure_string generate_passphrase(const passphrase_options& options);

// Strength in bits (word choice, plus the digit and its position if enabled).
double passphrase_entropy_bits(const passphrase_options& options);

std::size_t passphrase_wordlist_size();
std::string_view passphrase_word(std::size_t index);

} // namespace pb

#endif // PB_PASSPHRASE_GENERATOR_H_
