#include "web/site_match.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>

using namespace pb::web;

namespace {

std::optional<std::string> domain_of(const char* host) {
    const auto normalized = normalize_host(host);
    if (!normalized) return std::nullopt;
    return registrable_domain(*normalized);
}

match_kind match_urls(const char* saved, const char* page) {
    const auto s = parse_site(saved, true);
    const auto p = parse_site(page);
    if (!s || !p) return match_kind::none;
    return match(*s, *p);
}

} // namespace

TEST(Punycode, Rfc3492Samples) {
    EXPECT_EQ(punycode_encode("münchen"), "mnchen-3ya");
    EXPECT_EQ(punycode_encode("bücher"), "bcher-kva");
    EXPECT_EQ(punycode_encode("公司"), "55qx5d");
    EXPECT_EQ(punycode_encode("食狮"), "85x722f");
    EXPECT_EQ(punycode_encode("ελ"), "qxam");
    EXPECT_EQ(punycode_encode("\xC3\x28"), std::nullopt); // invalid UTF-8
}

TEST(NormalizeHost, AsciiFormOfHosts) {
    EXPECT_EQ(normalize_host("WWW.Example.COM."), "www.example.com");
    EXPECT_EQ(normalize_host("münchen.de"), "xn--mnchen-3ya.de");
    EXPECT_EQ(normalize_host("[::1]"), "[::1]");
    EXPECT_EQ(normalize_host(""), std::nullopt);
    EXPECT_EQ(normalize_host("a..b"), std::nullopt);
    EXPECT_EQ(normalize_host("exa mple.com"), std::nullopt);
    EXPECT_EQ(normalize_host(std::string(64, 'a') + ".com"), std::nullopt);
}

TEST(PublicSuffix, RulesAreCompiledIn) { EXPECT_GT(public_suffix_rule_count(), 5000u); }

// Cases from the Public Suffix List's own test suite (test_psl.txt).
TEST(PublicSuffix, RegistrableDomains) {
    EXPECT_EQ(domain_of("example.com"), "example.com");
    EXPECT_EQ(domain_of("www.example.com"), "example.com");
    EXPECT_EQ(domain_of("com"), std::nullopt);
    EXPECT_EQ(domain_of("example.uk.com"), "example.uk.com");
    EXPECT_EQ(domain_of("a.b.example.uk.com"), "example.uk.com");
    EXPECT_EQ(domain_of("uk.com"), std::nullopt);
    EXPECT_EQ(domain_of("www.example.co.uk"), "example.co.uk");
    EXPECT_EQ(domain_of("co.uk"), std::nullopt);
    // Wildcard and exception rules.
    EXPECT_EQ(domain_of("c.kobe.jp"), std::nullopt);
    EXPECT_EQ(domain_of("b.c.kobe.jp"), "b.c.kobe.jp");
    EXPECT_EQ(domain_of("city.kobe.jp"), "city.kobe.jp");
    EXPECT_EQ(domain_of("www.city.kobe.jp"), "city.kobe.jp");
    EXPECT_EQ(domain_of("test.k12.ak.us"), "test.k12.ak.us");
    EXPECT_EQ(domain_of("k12.ak.us"), std::nullopt);
    // Unicode rules.
    EXPECT_EQ(domain_of("食狮.com.cn"), "xn--85x722f.com.cn");
    EXPECT_EQ(domain_of("食狮.公司.cn"), "xn--85x722f.xn--55qx5d.cn");
    EXPECT_EQ(domain_of("www.食狮.公司.cn"), "xn--85x722f.xn--55qx5d.cn");
    EXPECT_EQ(domain_of("公司.cn"), std::nullopt);
    // Private section: each user site is its own domain.
    EXPECT_EQ(domain_of("alice.github.io"), "alice.github.io");
    EXPECT_EQ(domain_of("github.io"), std::nullopt);
    // Unknown TLDs use the default rule; single labels and IPs have none.
    EXPECT_EQ(domain_of("router.internal"), "router.internal");
    EXPECT_EQ(domain_of("localhost"), std::nullopt);
    EXPECT_EQ(domain_of("192.168.0.1"), std::nullopt);
}

TEST(ParseSite, AbsoluteAndSavedAddresses) {
    const auto a = parse_site("HTTPS://user:pw@WWW.Example.COM.:8443/login?x#y");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->scheme, "https");
    EXPECT_EQ(a->host, "www.example.com");
    EXPECT_EQ(a->port, 8443);

    const auto b = parse_site("https://example.com:443/");
    ASSERT_TRUE(b);
    EXPECT_FALSE(b->port); // default port

    EXPECT_FALSE(parse_site("example.com/login"));
    const auto c = parse_site("example.com/login", true);
    ASSERT_TRUE(c);
    EXPECT_EQ(c->scheme, "https");
    EXPECT_EQ(c->host, "example.com");

    const auto v6 = parse_site("http://[::1]:8080/");
    ASSERT_TRUE(v6);
    EXPECT_EQ(v6->host, "[::1]");
    EXPECT_EQ(v6->port, 8080);

    EXPECT_FALSE(parse_site("ftp://example.com"));
    EXPECT_FALSE(parse_site("javascript:alert(1)", true));
    EXPECT_FALSE(parse_site("https://example.com:99999/"));
    EXPECT_FALSE(parse_site("https:///path"));
}

TEST(SiteMatch, SameHostAndSameRegistrableDomain) {
    EXPECT_EQ(match_urls("https://example.com", "https://example.com/login"), match_kind::exact);
    EXPECT_EQ(match_urls("example.com", "https://example.com/login"), match_kind::exact);
    EXPECT_EQ(match_urls("https://accounts.google.com", "https://mail.google.com/"), match_kind::domain);
    EXPECT_EQ(match_urls("https://münchen.de", "https://www.xn--mnchen-3ya.de/"), match_kind::domain);
}

TEST(SiteMatch, PhishingLookalikesDoNotMatch) {
    EXPECT_EQ(match_urls("https://example.com", "https://example.com.evil.net/"), match_kind::none);
    EXPECT_EQ(match_urls("https://example.com", "https://examp1e.com/"), match_kind::none);
    EXPECT_EQ(match_urls("https://example.co.uk", "https://other.co.uk/"), match_kind::none);
    EXPECT_EQ(match_urls("https://alice.github.io", "https://mallory.github.io/"), match_kind::none);
}

TEST(SiteMatch, NoDowngradeToHttp) {
    EXPECT_EQ(match_urls("https://example.com", "http://example.com/"), match_kind::none);
    EXPECT_EQ(match_urls("example.com", "http://example.com/"), match_kind::none);
    EXPECT_EQ(match_urls("http://example.com", "http://example.com/"), match_kind::exact);
    EXPECT_EQ(match_urls("http://example.com", "https://example.com/"), match_kind::exact);
}

TEST(SiteMatch, PortsAndHostsWithoutDomain) {
    EXPECT_EQ(match_urls("https://192.168.0.1:8443", "https://192.168.0.1:8443/x"), match_kind::exact);
    EXPECT_EQ(match_urls("https://192.168.0.1:8443", "https://192.168.0.1/"), match_kind::none);
    EXPECT_EQ(match_urls("https://192.168.0.1", "https://192.168.0.2/"), match_kind::none);
    EXPECT_EQ(match_urls("https://example.com:8443", "https://example.com/"), match_kind::none);
    EXPECT_EQ(match_urls("https://example.com:8443", "https://www.example.com:8443/"), match_kind::domain);
    EXPECT_EQ(match_urls("http://localhost:3000", "http://localhost:3000/"), match_kind::exact);
    EXPECT_EQ(match_urls("http://localhost:3000", "http://localhost:3001/"), match_kind::none);
    EXPECT_EQ(match_urls("https://a.localhost", "https://b.localhost/"), match_kind::none);
}
