#include "crypto/password_generator.h"

#include "crypto/crypto.h"

#include <sodium.h>

#include <stdexcept>
#include <string_view>
#include <vector>

namespace pb {

namespace {

constexpr std::string_view LOWER = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view DIGITS = "0123456789";
constexpr std::string_view SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
constexpr std::string_view AMBIGUOUS = "0Oo1lI|`'\"";

std::string filtered(std::string_view set, bool avoid_ambiguous) {
    std::string out;
    for (const char c : set) {
        if (avoid_ambiguous && AMBIGUOUS.find(c) != std::string_view::npos) continue;
        out += c;
    }
    return out;
}

std::vector<std::string> classes(const password_options& o) {
    std::vector<std::string> out;
    if (o.lowercase) out.push_back(filtered(LOWER, o.avoid_ambiguous));
    if (o.uppercase) out.push_back(filtered(UPPER, o.avoid_ambiguous));
    if (o.digits) out.push_back(filtered(DIGITS, o.avoid_ambiguous));
    if (o.symbols) out.push_back(filtered(SYMBOLS, o.avoid_ambiguous));
    return out;
}

char pick(std::string_view set) {
    return set[randombytes_uniform(static_cast<std::uint32_t>(set.size()))];
}

} // namespace

std::string password_alphabet(const password_options& options) {
    std::string all;
    for (const auto& c : classes(options)) all += c;
    return all;
}

secure_string generate_password(const password_options& options) {
    crypto::ensure_initialized();
    if (options.length < password_options::MIN_LENGTH ||
        options.length > password_options::MAX_LENGTH) {
        throw std::invalid_argument("password length out of range");
    }
    const auto sets = classes(options);
    if (sets.empty()) throw std::invalid_argument("select at least one character class");
    const std::string all = password_alphabet(options);

    secure_string out;
    out.reserve(options.length);
    for (const auto& set : sets) out += pick(set); // one of each selected class
    while (out.size() < options.length) out += pick(all);

    // Fisher-Yates shuffle so the guaranteed characters are not at the start.
    for (std::size_t i = out.size() - 1; i > 0; --i) {
        const std::size_t j = randombytes_uniform(static_cast<std::uint32_t>(i + 1));
        std::swap(out[i], out[j]);
    }
    return out;
}

} // namespace pb
