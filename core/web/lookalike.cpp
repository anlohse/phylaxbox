#include "web/lookalike.h"

#include <algorithm>
#include <string_view>

namespace pb::web {

namespace {

constexpr std::size_t MIN_FUZZY = 5;   // shorter names: equality only
constexpr std::size_t LONG_NAME = 10;  // from here, two edits are allowed
constexpr std::size_t MAX_RESULTS = 3;

// Characters that look like a lowercase ASCII letter (a pragmatic subset of
// Unicode TR39 confusables: Cyrillic, Greek, Armenian, IPA, accented Latin).
char32_t fold(char32_t c) {
    if (c < 0x80) return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
    switch (c) {
    // Latin-1 and Latin Extended-A letters with diacritics
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5: case 0x101: case 0x103: case 0x105: return 'a';
    case 0xE7: case 0x107: case 0x109: case 0x10B: case 0x10D: return 'c';
    case 0xE8: case 0xE9: case 0xEA: case 0xEB: case 0x113: case 0x117: case 0x119: case 0x11B: return 'e';
    case 0xEC: case 0xED: case 0xEE: case 0xEF: case 0x129: case 0x12B: case 0x12F: case 0x131: return 'i';
    case 0xF1: case 0x144: case 0x146: case 0x148: return 'n';
    case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: case 0xF8: case 0x14D: case 0x151: return 'o';
    case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0x16B: case 0x16F: case 0x171: case 0x173: return 'u';
    case 0xFD: case 0xFF: return 'y';
    case 0x15B: case 0x15F: case 0x161: return 's';
    case 0x17A: case 0x17C: case 0x17E: return 'z';
    case 0x142: return 'l';
    case 0x237: return 'j';
    // IPA
    case 0x251: return 'a';
    case 0x261: return 'g';
    case 0x269: return 'i';
    // Greek
    case 0x3B1: return 'a';
    case 0x3B9: return 'i';
    case 0x3BA: return 'k';
    case 0x3BD: return 'v';
    case 0x3BF: return 'o';
    case 0x3C1: return 'p';
    case 0x3C5: return 'u';
    case 0x3C7: return 'x';
    // Cyrillic
    case 0x430: return 'a';
    case 0x435: return 'e';
    case 0x43E: return 'o';
    case 0x440: return 'p';
    case 0x441: return 'c';
    case 0x443: return 'y';
    case 0x445: return 'x';
    case 0x455: return 's';
    case 0x456: return 'i';
    case 0x458: return 'j';
    case 0x4BB: return 'h';
    case 0x4CF: return 'l';
    case 0x501: return 'd';
    case 0x51B: return 'q';
    case 0x51D: return 'w';
    // Armenian
    case 0x570: return 'h';
    case 0x578: return 'n';
    case 0x57D: return 'u';
    case 0x585: return 'o';
    default: return c;
    }
}

void replace_all(std::u32string& s, std::u32string_view from, std::u32string_view to) {
    for (std::size_t pos = 0; (pos = s.find(from, pos)) != std::u32string::npos; pos += to.size()) {
        s.replace(pos, from.size(), to);
    }
}

// Optimal string alignment distance (Damerau-Levenshtein without repeated
// edits of one substring), capped work since names are short.
std::size_t distance(const std::u32string& a, const std::u32string& b) {
    const std::size_t n = a.size(), m = b.size();
    std::vector<std::vector<std::size_t>> d(n + 1, std::vector<std::size_t>(m + 1));
    for (std::size_t i = 0; i <= n; ++i) d[i][0] = i;
    for (std::size_t j = 0; j <= m; ++j) d[0][j] = j;
    for (std::size_t i = 1; i <= n; ++i) {
        for (std::size_t j = 1; j <= m; ++j) {
            const std::size_t cost = a[i - 1] == b[j - 1] ? 0 : 1;
            d[i][j] = std::min({d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost});
            if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) {
                d[i][j] = std::min(d[i][j], d[i - 2][j - 2] + 1);
            }
        }
    }
    return d[n][m];
}

std::string domain_of(const std::string& host) {
    const auto domain = registrable_domain(host);
    return domain ? *domain : host;
}

std::string first_label(const std::string& domain) { return domain.substr(0, domain.find('.')); }

std::vector<std::string> split(const std::string& s, const char* separators) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto pos = s.find_first_of(separators, start);
        const std::string part = s.substr(start, pos == std::string::npos ? std::string::npos : pos - start);
        if (!part.empty()) out.push_back(part);
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return out;
}

} // namespace

std::u32string lookalike_skeleton(const std::string& label) {
    std::u32string cps;
    if (label.rfind("xn--", 0) == 0) {
        if (auto decoded = punycode_decode(std::string_view(label).substr(4))) cps = std::move(*decoded);
    }
    if (cps.empty()) {
        for (unsigned char c : label) cps.push_back(c);
    }
    std::u32string out;
    for (char32_t c : cps) {
        c = fold(c);
        if (c == '-') continue;
        if (c == '0') c = 'o';
        if (c == '1') c = 'l';
        out.push_back(c);
    }
    replace_all(out, U"rn", U"m");
    replace_all(out, U"vv", U"w");
    return out;
}

std::vector<std::string> lookalikes(const site& page, const std::vector<site>& saved) {
    std::vector<std::string> found;
    if (is_ip_literal(page.host) || !registrable_domain(page.host)) return found;
    const std::string page_domain = domain_of(page.host);
    const std::u32string page_name = lookalike_skeleton(first_label(page_domain));
    std::vector<std::u32string> page_tokens;
    for (const auto& token : split(page.host, ".-")) page_tokens.push_back(lookalike_skeleton(token));

    for (const auto& s : saved) {
        if (found.size() >= MAX_RESULTS) break;
        if (is_ip_literal(s.host)) continue;
        const std::string saved_domain = domain_of(s.host);
        if (saved_domain == page_domain) continue; // the same site, not an imitation
        if (std::find(found.begin(), found.end(), saved_domain) != found.end()) continue;
        const std::u32string name = lookalike_skeleton(first_label(saved_domain));
        if (name.empty()) continue;

        bool alike = name == page_name;
        if (!alike && name.size() >= MIN_FUZZY) {
            alike = distance(name, page_name) <= (name.size() >= LONG_NAME ? 2u : 1u) ||
                    std::find(page_tokens.begin(), page_tokens.end(), name) != page_tokens.end();
        }
        if (alike) found.push_back(saved_domain);
    }
    return found;
}

} // namespace pb::web
