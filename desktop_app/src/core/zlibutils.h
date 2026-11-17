#ifndef ZLIBUTILS_H_
#define ZLIBUTILS_H_

#include "secure_bytes.h"

#include <cstddef>

namespace pb::zlib {

// Upper bound for the compressed size of `input_size` bytes.
std::size_t compress_bound(std::size_t input_size);

// Compresses `input` (zlib stream, RFC 1950) into `out` and returns the number
// of bytes written. `out_capacity` must be at least compress_bound(input.size).
std::size_t compress(byte_view input, std::uint8_t* out, std::size_t out_capacity);

// Inflates `input` into exactly `out_size` bytes. Throws vault_format_exception
// if the stream is invalid or does not inflate to exactly `out_size` bytes.
void decompress_exact(byte_view input, std::uint8_t* out, std::size_t out_size);

} // namespace pb::zlib

#endif /* ZLIBUTILS_H_ */
