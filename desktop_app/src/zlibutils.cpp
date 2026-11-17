/*
 * zlibutils.cpp
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */

#include "zlibutils.h"
#include <stdexcept>
#include <zlib.h>

// Função de compressão usando zlib (gzip)
std::vector<unsigned char> compressData(const std::string& data) {
    uLongf compressedSize = compressBound(data.size());
    std::vector<unsigned char> compressedData(compressedSize);

    if (compress(compressedData.data(), &compressedSize, reinterpret_cast<const Bytef*>(data.c_str()), data.size()) != Z_OK) {
        throw std::runtime_error("Erro ao comprimir os dados.");
    }

    compressedData.resize(compressedSize);
    return compressedData;
}

// Função de descompressão usando zlib (gzip)
std::string decompressData(const std::vector<unsigned char>& compressedData) {
    uLongf decompressedSize = compressedData.size() * 5;  // Tentar um tamanho grande o suficiente
    std::vector<unsigned char> decompressedData(decompressedSize);

    if (uncompress(decompressedData.data(), &decompressedSize, compressedData.data(), compressedData.size()) != Z_OK) {
        throw std::runtime_error("Erro ao descomprimir os dados.");
    }

    return std::string(decompressedData.begin(), decompressedData.begin() + decompressedSize);
}
