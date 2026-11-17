/*
 * Crypto.h
 *
 *  Created on: 12 de fev. de 2025
 *      Author: alanl
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#ifndef SODIUM_STATIC
#  define SODIUM_STATIC
#endif

#include <sodium.h>
#include <vector>
#include <string>

class Crypto {
public:
    
    static bool generateKeyFromPassword(const std::string& password, const std::vector<unsigned char>& storedSalt, std::vector<unsigned char>& key);
    static bool encryptData(const std::vector<unsigned char>& key, std::vector<unsigned char>& plaintext, std::vector<unsigned char>& ciphertext);
    static bool decryptData(const std::vector<unsigned char>& key, const std::vector<unsigned char>& ciphertext, std::vector<unsigned char> plaintext);

private:
    static bool sodium_initiated;
    static constexpr size_t SALT_SIZE = crypto_pwhash_SALTBYTES;
    static void init();
};

#endif /* CRYPTO_H_ */
