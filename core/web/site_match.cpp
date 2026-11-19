#include "web/site_match.h"

#include "public_suffix_list.h" // generated from core/web/data/public_suffix_list.dat

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

namespace pb::web {

namespace {

constexpr std::size_t MAX_HOST = 253;
constexpr std::size_t MAX_LABEL = 63;

bool is_ascii(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
}

std::string ascii_lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

std::string trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(first, last - first + 1));
}

std::vector<std::string_view> split_labels(std::string_view host) {
    std::vector<std::string_view> labels;
    std::size_t start = 0;
    for (;;) {
        const auto dot = host.find('.', start);
        labels.push_back(host.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start));
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }
    return labels;
}

// Strict UTF-8 decoding (no overlongs, surrogates or values above U+10FFFF).
std::optional<std::u32string> decode_utf8(std::string_view s) {
    std::u32string out;
    for (std::size_t i = 0; i < s.size();) {
        const auto b0 = static_cast<unsigned char>(s[i]);
        char32_t cp = 0;
        std::size_t len = 0;
        if (b0 < 0x80) { cp = b0; len = 1; }
        else if ((b0 & 0xE0) == 0xC0) { cp = b0 & 0x1F; len = 2; }
        else if ((b0 & 0xF0) == 0xE0) { cp = b0 & 0x0F; len = 3; }
        else if ((b0 & 0xF8) == 0xF0) { cp = b0 & 0x07; len = 4; }
        else return std::nullopt;
        if (i + len > s.size()) return std::nullopt;
        for (std::size_t k = 1; k < len; ++k) {
            const auto b = static_cast<unsigned char>(s[i + k]);
            if ((b & 0xC0) != 0x80) return std::nullopt;
            cp = (cp << 6) | (b & 0x3F);
        }
        static constexpr char32_t min_for_len[] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp < min_for_len[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return std::nullopt;
        out.push_back(cp);
        i += len;
    }
    return out;
}

bool valid_ascii_label(std::string_view label) {
    if (label.empty() || label.size() > MAX_LABEL) return false;
    return std::all_of(label.begin(), label.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}

bool all_digits(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// The Public Suffix List as three sets: plain rules, wildcard rules ("*.ck"
// stored as "ck") and exception rules ("!www.ck" stored as "www.ck"), all in
// their normalized (punycode) form.
struct suffix_rules {
    std::unordered_set<std::string> plain;
    std::unordered_set<std::string> wildcard;
    std::unordered_set<std::string> exception;
    std::size_t count = 0;

    suffix_rules() {
        for (const char* raw : PUBLIC_SUFFIX_RULES) {
            std::string_view rule(raw);
            auto* target = &plain;
            if (rule.rfind("*.", 0) == 0) {
                target = &wildcard;
                rule.remove_prefix(2);
            } else if (rule.rfind("!", 0) == 0) {
                target = &exception;
                rule.remove_prefix(1);
            }
            if (auto host = normalize_host(rule)) {
                target->insert(std::move(*host));
                ++count;
            }
        }
    }
};

const suffix_rules& rules() {
    static const suffix_rules instance;
    return instance;
}

std::string join_from(const std::vector<std::string_view>& labels, std::size_t first) {
    std::string out;
    for (std::size_t i = first; i < labels.size(); ++i) {
        if (!out.empty()) out.push_back('.');
        out.append(labels[i]);
    }
    return out;
}

// Index of the first label of the public suffix.
std::size_t public_suffix_start(const std::vector<std::string_view>& labels) {
    const auto& r = rules();
    // Longest suffix first: the first rule found is the prevailing one, and an
    // exception rule beats the wildcard it carves out of.
    for (std::size_t i = 0; i < labels.size(); ++i) {
        const std::string suffix = join_from(labels, i);
        if (r.exception.count(suffix)) return i + 1;
        if (r.plain.count(suffix)) return i;
        if (i + 1 < labels.size() && r.wildcard.count(join_from(labels, i + 1))) return i;
    }
    return labels.size() - 1; // default rule "*"
}

} // namespace

std::optional<std::string> punycode_encode(std::string_view utf8_label) {
    const auto input = decode_utf8(utf8_label);
    if (!input) return std::nullopt;

    constexpr std::uint32_t base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
    auto digit = [](std::uint32_t d) { return static_cast<char>(d < 26 ? 'a' + d : '0' + (d - 26)); };
    auto adapt = [&](std::uint32_t delta, std::uint32_t points, bool first) {
        delta = first ? delta / damp : delta / 2;
        delta += delta / points;
        std::uint32_t k = 0;
        while (delta > ((base - tmin) * tmax) / 2) {
            delta /= base - tmin;
            k += base;
        }
        return k + (base - tmin + 1) * delta / (delta + skew);
    };

    std::string out;
    for (char32_t c : *input) {
        if (c < 0x80) out.push_back(static_cast<char>(c));
    }
    const auto basic = static_cast<std::uint32_t>(out.size());
    std::uint32_t handled = basic;
    if (basic > 0) out.push_back('-');

    std::uint32_t n = 0x80, delta = 0, bias = 72;
    const auto total = static_cast<std::uint32_t>(input->size());
    while (handled < total) {
        char32_t m = 0x10FFFF + 1;
        for (char32_t c : *input) {
            if (c >= n && c < m) m = c;
        }
        const std::uint64_t step = static_cast<std::uint64_t>(m - n) * (handled + 1);
        if (step > 0xFFFFFFFFull - delta) return std::nullopt; // overflow
        delta += static_cast<std::uint32_t>(step);
        n = static_cast<std::uint32_t>(m);
        for (char32_t c : *input) {
            if (c < n && ++delta == 0) return std::nullopt;
            if (c == n) {
                std::uint32_t q = delta;
                for (std::uint32_t k = base;; k += base) {
                    const std::uint32_t t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
                    if (q < t) break;
                    out.push_back(digit(t + (q - t) % (base - t)));
                    q = (q - t) / (base - t);
                }
                out.push_back(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                ++handled;
            }
        }
        ++delta;
        ++n;
    }
    return out;
}

std::optional<std::u32string> punycode_decode(std::string_view input) {
    constexpr std::uint32_t base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
    auto adapt = [&](std::uint32_t delta, std::uint32_t points, bool first) {
        delta = first ? delta / damp : delta / 2;
        delta += delta / points;
        std::uint32_t k = 0;
        while (delta > ((base - tmin) * tmax) / 2) {
            delta /= base - tmin;
            k += base;
        }
        return k + (base - tmin + 1) * delta / (delta + skew);
    };
    std::u32string out;
    std::size_t pos = 0;
    if (const auto dash = input.rfind('-'); dash != std::string_view::npos) {
        for (std::size_t j = 0; j < dash; ++j) {
            if (static_cast<unsigned char>(input[j]) >= 0x80) return std::nullopt;
            out.push_back(static_cast<char32_t>(input[j]));
        }
        pos = dash + 1;
    }
    std::uint32_t n = 0x80, i = 0, bias = 72;
    while (pos < input.size()) {
        const std::uint32_t old_i = i;
        std::uint32_t w = 1;
        for (std::uint32_t k = base;; k += base) {
            if (pos >= input.size()) return std::nullopt;
            const char c = input[pos++];
            std::uint32_t digit;
            if (c >= 'a' && c <= 'z') digit = static_cast<std::uint32_t>(c - 'a');
            else if (c >= 'A' && c <= 'Z') digit = static_cast<std::uint32_t>(c - 'A');
            else if (c >= '0' && c <= '9') digit = static_cast<std::uint32_t>(c - '0') + 26;
            else return std::nullopt;
            if (digit > (0xFFFFFFFFu - i) / w) return std::nullopt;
            i += digit * w;
            const std::uint32_t t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
            if (digit < t) break;
            if (w > 0xFFFFFFFFu / (base - t)) return std::nullopt;
            w *= base - t;
        }
        const auto len = static_cast<std::uint32_t>(out.size()) + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        if (i / len > 0x10FFFFu - n) return std::nullopt;
        n += i / len;
        i %= len;
        if (n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF)) return std::nullopt;
        out.insert(out.begin() + i, static_cast<char32_t>(n));
        ++i;
    }
    return out;
}

std::optional<std::string> normalize_host(std::string_view raw) {
    std::string host = trim(raw);
    if (!host.empty() && host.back() == '.') host.pop_back();
    if (host.empty()) return std::nullopt;

    if (host.front() == '[') { // IPv6 literal
        if (host.size() < 4 || host.back() != ']') return std::nullopt;
        host = ascii_lower(host);
        const bool ok = std::all_of(host.begin() + 1, host.end() - 1, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':' || c == '.';
        });
        return ok ? std::optional<std::string>(host) : std::nullopt;
    }

    std::string out;
    for (auto label : split_labels(host)) {
        std::string part;
        if (is_ascii(label)) {
            part = ascii_lower(label);
        } else {
            const auto encoded = punycode_encode(ascii_lower(label));
            if (!encoded) return std::nullopt;
            part = "xn--" + *encoded;
        }
        if (!valid_ascii_label(part)) return std::nullopt;
        if (!out.empty()) out.push_back('.');
        out += part;
    }
    if (out.size() > MAX_HOST) return std::nullopt;
    return out;
}

bool is_ip_literal(std::string_view host) {
    if (!host.empty() && host.front() == '[') return true;
    const auto labels = split_labels(host);
    if (labels.size() != 4) return false;
    return std::all_of(labels.begin(), labels.end(), [](std::string_view part) {
        return all_digits(part) && part.size() <= 3 && std::stoi(std::string(part)) <= 255;
    });
}

std::string public_suffix(std::string_view host) {
    const auto labels = split_labels(host);
    return join_from(labels, public_suffix_start(labels));
}

std::optional<std::string> registrable_domain(std::string_view host) {
    if (host.empty() || is_ip_literal(host)) return std::nullopt;
    const auto labels = split_labels(host);
    const std::size_t start = public_suffix_start(labels);
    if (start == 0) return std::nullopt; // the host is a public suffix
    return join_from(labels, start - 1);
}

std::size_t public_suffix_rule_count() { return rules().count; }

std::optional<site> parse_site(std::string_view url, bool assume_https) {
    const std::string text = trim(url);
    site out;
    std::string_view rest;
    if (const auto sep = text.find("://"); sep != std::string::npos) {
        out.scheme = ascii_lower(std::string_view(text).substr(0, sep));
        rest = std::string_view(text).substr(sep + 3);
    } else if (assume_https) {
        out.scheme = "https";
        rest = text;
    } else {
        return std::nullopt;
    }
    if (out.scheme != "http" && out.scheme != "https") return std::nullopt;

    std::string_view authority = rest.substr(0, rest.find_first_of("/?#\\"));
    if (const auto at = authority.rfind('@'); at != std::string_view::npos) authority.remove_prefix(at + 1);

    std::string_view host = authority;
    std::string_view port;
    if (!authority.empty() && authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        host = authority.substr(0, close + 1);
        const auto after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after.front() != ':') return std::nullopt;
            port = after.substr(1);
        }
    } else if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        host = authority.substr(0, colon);
        port = authority.substr(colon + 1);
    }

    const auto normalized = normalize_host(host);
    if (!normalized) return std::nullopt;
    out.host = *normalized;
    if (!port.empty()) {
        if (!all_digits(port) || port.size() > 5) return std::nullopt;
        const unsigned long value = std::stoul(std::string(port));
        if (value == 0 || value > 65535) return std::nullopt;
        out.port = static_cast<std::uint16_t>(value);
        if (*out.port == (out.scheme == "http" ? 80 : 443)) out.port.reset();
    }
    return out;
}

match_kind match(const site& saved, const site& page) {
    if (page.scheme != "http" && page.scheme != "https") return match_kind::none;
    if (saved.scheme == "https" && page.scheme == "http") return match_kind::none;

    if (saved.port && *saved.port != page.effective_port()) return match_kind::none;
    if (saved.host == page.host) return match_kind::exact;
    const auto saved_domain = registrable_domain(saved.host);
    if (!saved_domain) return match_kind::none;
    const auto page_domain = registrable_domain(page.host);
    return page_domain && *page_domain == *saved_domain ? match_kind::domain : match_kind::none;
}

} // namespace pb::web
