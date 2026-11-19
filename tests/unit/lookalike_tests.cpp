#include "web/lookalike.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace pb::web;

namespace {

std::vector<std::string> alike(const char* page, std::vector<const char*> saved) {
    std::vector<site> sites;
    for (const char* s : saved) {
        if (auto parsed = parse_site(s, true)) sites.push_back(*parsed);
    }
    const auto p = parse_site(page);
    return p ? lookalikes(*p, sites) : std::vector<std::string>{};
}

const std::vector<std::string> kPaypal = {"paypal.com"};

} // namespace

TEST(Punycode, DecodesWhatItEncodes) {
    EXPECT_EQ(punycode_decode("mnchen-3ya"), std::u32string(U"münchen"));
    EXPECT_EQ(punycode_decode("55qx5d"), std::u32string(U"公司"));
    EXPECT_EQ(punycode_decode("abc-"), std::u32string(U"abc"));
    EXPECT_EQ(punycode_decode("bcher-k!a"), std::nullopt);
    const std::vector<std::pair<const char*, std::u32string>> words = {
        {"pаypal", U"pаypal"}, {"ελληνικά", U"ελληνικά"}, {"日本語", U"日本語"}, {"ñandú", U"ñandú"}};
    for (const auto& [utf8, code_points] : words) {
        const auto encoded = punycode_encode(utf8);
        ASSERT_TRUE(encoded) << utf8;
        EXPECT_EQ(punycode_decode(*encoded), code_points) << utf8;
    }
}

TEST(Lookalike, Skeletons) {
    EXPECT_EQ(lookalike_skeleton("PayPa1"), U"paypal");
    EXPECT_EQ(lookalike_skeleton("rnicrosoft"), U"microsoft");
    EXPECT_EQ(lookalike_skeleton("pay-pal"), U"paypal");
    EXPECT_EQ(lookalike_skeleton("g00gle"), U"google");
    EXPECT_EQ(lookalike_skeleton("vvikipedia"), U"wikipedia");
    // Cyrillic "а" in "pаypal", given in its punycode form.
    const auto host = normalize_host("pаypal");
    ASSERT_TRUE(host);
    EXPECT_EQ(host->rfind("xn--", 0), 0u);
    EXPECT_EQ(lookalike_skeleton(*host), U"paypal");
}

TEST(Lookalike, Homographs) {
    EXPECT_EQ(alike("https://pаypal.com/", {"https://www.paypal.com"}), kPaypal); // Cyrillic а
    EXPECT_EQ(alike("https://paypa1.com/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://pàypal.com/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://pay-pal.com/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://rnicrosoft.com/", {"login.microsoft.com"}), std::vector<std::string>{"microsoft.com"});
}

TEST(Lookalike, OtherSuffixAndTypos) {
    EXPECT_EQ(alike("https://paypal.co/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://www.paypal.com.br/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://paypall.com/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://payapl.com/", {"paypal.com"}), kPaypal); // swapped letters
    EXPECT_EQ(alike("https://mercadolivre.com/", {"mercadolivre.com.br"}),
              std::vector<std::string>{"mercadolivre.com.br"});
    EXPECT_EQ(alike("https://mercadolivrre.com.br/", {"mercadolivre.com.br"}),
              std::vector<std::string>{"mercadolivre.com.br"});
    EXPECT_EQ(alike("https://mercadolivvrre.com.br/", {"mercadolivre.com.br"}),
              std::vector<std::string>{"mercadolivre.com.br"}) << "two edits for long names";
}

TEST(Lookalike, SavedNameInsideAnotherHost) {
    EXPECT_EQ(alike("https://paypal.com.example.net/", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://secure-paypal.example.net/login", {"paypal.com"}), kPaypal);
    EXPECT_EQ(alike("https://login.paypal-verify.net/", {"paypal.com"}), kPaypal);
}

TEST(Lookalike, NotForTheSameOrUnrelatedSites) {
    EXPECT_TRUE(alike("https://www.paypal.com/", {"https://paypal.com"}).empty());
    EXPECT_TRUE(alike("https://github.com/", {"google.com"}).empty());
    EXPECT_TRUE(alike("https://amazing.com/", {"amazon.com"}).empty());
    EXPECT_TRUE(alike("https://tank.com/", {"bank.com"}).empty()) << "short names: equality only";
    EXPECT_TRUE(alike("https://mail.example.com/", {"mail.com"}).empty()) << "short names are not searched in hosts";
    EXPECT_TRUE(alike("http://localhost:3000/", {"http://localhost:3001"}).empty());
    EXPECT_TRUE(alike("https://192.168.0.2/", {"https://192.168.0.1"}).empty());
}

TEST(Lookalike, AtMostThreeDistinctResults) {
    const auto r = alike("https://paypal.example.org/",
                         {"paypal.com", "www.paypal.com", "paypal.de", "paypal.fr", "paypal.it"});
    EXPECT_EQ(r, (std::vector<std::string>{"paypal.com", "paypal.de", "paypal.fr"}));
}
