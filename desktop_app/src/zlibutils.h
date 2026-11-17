/*
 * zlibutils.h
 *
 *  Created on: 15 de fev. de 2025
 *      Author: alanl
 */

#ifndef ZLIBUTILS_H_
#define ZLIBUTILS_H_

#include <string>
#include <vector>

std::vector<unsigned char> compressData(const std::string& data);

// Função de descompressão usando zlib (gzip)
std::string decompressData(const std::vector<unsigned char>& compressedData);

#endif /* ZLIBUTILS_H_ */
