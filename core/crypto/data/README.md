# Third-party data

## EFF Long Wordlist — `eff_large_wordlist.txt`

* Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>,
  described in <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>
* © Electronic Frontier Foundation, licensed under
  [Creative Commons Attribution 3.0 United States (CC BY 3.0 US)](https://creativecommons.org/licenses/by/3.0/us/)
* Unmodified. SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`,
  7 776 lines `<5 dice digits>\t<word>`.

Used by the passphrase generator (`core/crypto/passphrase_generator.cpp`); the build turns
it into a C++ array and checks the word count. The application credits it in its
"About" section.
