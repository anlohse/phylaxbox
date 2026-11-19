#ifndef PB_LOOKALIKE_H_
#define PB_LOOKALIKE_H_

#include "web/site_match.h"

#include <string>
#include <vector>

// Phishing heuristics (spec §8.5): does the page's domain imitate a site the
// user has logins for? Used to warn, never to block: a legitimate site can
// look like another one (example.com / example.com.br).
namespace pb::web {

// The registrable domains of `saved` sites (or their hosts, when they have
// none) that `page` seems to imitate without matching them:
//   * the same name once look-alike characters are folded: Cyrillic and
//     Greek homographs, accents, 0/o, 1/l, "rn"/"m", "vv"/"w", hyphens;
//     this includes the same name under another suffix (paypal.co);
//   * a name one character apart (two for names of 10 or more characters);
//   * the saved name used as a label of the page's host
//     (paypal.com.example.net, secure-paypal.example.net).
// Names shorter than 5 characters are only compared for equality. At most
// three results, in the order of `saved`.
std::vector<std::string> lookalikes(const site& page, const std::vector<site>& saved);

// The folded form used above, of one label given in ASCII (punycode labels
// are decoded first). Exposed for tests.
std::u32string lookalike_skeleton(const std::string& label);

} // namespace pb::web

#endif // PB_LOOKALIKE_H_
