/*
 * Crypto.cpp
 *
 *  Created on: 12 de fev. de 2025
 *      Author: alanl
 */

#include "Crypto.h"
#include <iostream>
#include <fstream>
#include <sodium.h>

bool Crypto::sodium_initiated = false;

void Crypto::init() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Falha ao inicializar o Libsodium.");
    }
    sodium_initiated = true;
}

// Gera uma chave a partir de uma senha e um salt armazenado
bool Crypto::generateKeyFromPassword(const std::string& password, const std::vector<unsigned char>& storedSalt, std::vector<unsigned char>& key) {
    if (!sodium_initiated) init();
    key.resize(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.length(),
                      storedSalt.data(), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        std::cerr << "Erro ao derivar chave da senha.\n";
        return false;
    }

    return true;
}


bool Crypto::encryptData(const std::vector<unsigned char>& key, std::vector<unsigned char>& plaintext, std::vector<unsigned char>& ciphertext) {
    if (!sodium_initiated) init(); 
    ciphertext.resize(crypto_secretbox_MACBYTES + plaintext.size());

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce); 

    if (crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), nonce, key.data()) != 0) {
        std::cerr << "Erro ao criptografar os dados.\n";
        return false;
    }

    ciphertext.insert(ciphertext.begin(), nonce, nonce + crypto_secretbox_NONCEBYTES);

    return true;
}


bool Crypto::decryptData(const std::vector<unsigned char>& key, const std::vector<unsigned char>& ciphertext, std::vector<unsigned char> plaintext) {
    if (!sodium_initiated) init();
    if (ciphertext.size() < crypto_secretbox_NONCEBYTES) {
        std::cerr << "Ciphertext inválido.\n";
        return false;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    std::copy(ciphertext.begin(), ciphertext.begin() + crypto_secretbox_NONCEBYTES, nonce);

    plaintext = std::vector<unsigned char>(ciphertext.size() - crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_open_easy(plaintext.data(), ciphertext.data() + crypto_secretbox_NONCEBYTES,
                                   ciphertext.size() - crypto_secretbox_NONCEBYTES, nonce, key.data()) != 0) {
        std::cerr << "Falha na descriptografia. Dados podem ter sido adulterados.\n";
        return false;
    }

    return true;
}
