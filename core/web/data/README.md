# Third-party data

## Public Suffix List — `public_suffix_list.dat`

* Source: <https://publicsuffix.org/list/public_suffix_list.dat>, maintained by the
  [Public Suffix List project](https://publicsuffix.org/) (Mozilla Foundation and contributors)
* Licensed under the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/)
* Unmodified copy downloaded on 2026-11-18. SHA-256
  `809adae1a2cb1621b70165c11e0d14412d3f104f40a4ebed9a99e23c54f78d71`.

Used to decide which saved logins belong to the site open in the browser
(`core/web/site_match.cpp`, spec §8.5). The build checks the SHA-256 and turns the rules
(ICANN and private sections) into a C++ array.

**Updating**: download the file again from the URL above (only from there), replace this
copy, and update the hash and date here and `PB_PSL_SHA256` in `core/CMakeLists.txt`. The
matching tests in `tests/unit/site_match_tests.cpp` must still pass.
