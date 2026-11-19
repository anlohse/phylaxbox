#ifndef PB_SITE_MATCH_H_
#define PB_SITE_MATCH_H_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

// Matching saved logins to the page the browser is showing (spec §8.5).
//
// Hosts are compared in their ASCII form: lowercase, Unicode labels converted
// to punycode ("xn--..."), as browsers report them. Two hosts belong to the
// same site when they share a registrable domain ("eTLD+1") according to the
// Public Suffix List (core/web/data), including its private section, so
// "alice.github.io" and "bob.github.io" are different sites.
namespace pb::web {

// Lowercases ASCII letters, converts non-ASCII labels to punycode and drops a
// trailing dot. Returns nullopt for anything that is not a valid host name
// (empty labels, characters outside [a-z0-9-_], more than 253 characters).
// Unicode labels are not otherwise normalized (no UTS #46 mapping): type
// them lowercase.
std::optional<std::string> normalize_host(std::string_view host);

// RFC 3492 encoding of one label given as UTF-8, without the "xn--" prefix.
// Returns nullopt for invalid UTF-8.
std::optional<std::string> punycode_encode(std::string_view utf8_label);

// Dotted IPv4 ("192.168.0.1") or bracketed IPv6 ("[::1]").
bool is_ip_literal(std::string_view host);

// The public suffix of a normalized host ("co.uk" for "a.b.co.uk"; the last
// label when no rule matches).
std::string public_suffix(std::string_view host);

// The registrable domain of a normalized host ("b.co.uk" for "a.b.co.uk").
// nullopt for IP literals and hosts that are themselves a public suffix.
std::optional<std::string> registrable_domain(std::string_view host);

// Number of rules compiled in (for tests and the About screen).
std::size_t public_suffix_rule_count();

struct site {
    std::string scheme; // "http" | "https" (others are not web sites)
    std::string host;   // normalized
    std::optional<std::uint16_t> port; // absent: the scheme's default port

    std::uint16_t effective_port() const { return port ? *port : (scheme == "http" ? 80 : 443); }
};

// Parses an absolute http(s) URL. With `assume_https`, a saved address
// without a scheme ("example.com/login") is read as https. Returns nullopt
// for other schemes and malformed URLs.
std::optional<site> parse_site(std::string_view url, bool assume_https = false);

enum class match_kind {
    none,
    domain, // same registrable domain
    exact,  // same host
};
// When the saved address names a port, the page must use that port.

// How well a saved address matches the page. Never matches when the saved
// address is https and the page is http (no downgrade). IP literals and
// hosts without a registrable domain ("localhost", "github.io") need an
// exact host match.
match_kind match(const site& saved, const site& page);

} // namespace pb::web

#endif // PB_SITE_MATCH_H_
