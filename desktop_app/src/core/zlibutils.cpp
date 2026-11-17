#include "zlibutils.h"

#include "pbexceptions.h"

#include <zlib.h>

#include <limits>
#include <stdexcept>

namespace pb::zlib {

namespace {
void check_fits_ulong(std::size_t n) {
    if (n > std::numeric_limits<uLong>::max()) {
        throw std::length_error("buffer too large for zlib");
    }
}
} // namespace

std::size_t compress_bound(std::size_t input_size) {
    check_fits_ulong(input_size);
    return static_cast<std::size_t>(::compressBound(static_cast<uLong>(input_size)));
}

std::size_t compress(byte_view input, std::uint8_t* out, std::size_t out_capacity) {
    check_fits_ulong(input.size);
    check_fits_ulong(out_capacity);
    uLongf out_len = static_cast<uLongf>(out_capacity);
    // compress2 does not accept a null source even for empty input.
    static const Bytef empty = 0;
    const Bytef* src = input.size ? input.data : &empty;
    if (::compress2(out, &out_len, src, static_cast<uLong>(input.size), Z_BEST_COMPRESSION) !=
        Z_OK) {
        throw std::runtime_error("zlib compression failed");
    }
    return static_cast<std::size_t>(out_len);
}

void decompress_exact(byte_view input, std::uint8_t* out, std::size_t out_size) {
    check_fits_ulong(input.size);
    check_fits_ulong(out_size);
    // uncompress() needs a writable, non-null buffer even for empty output.
    Bytef scratch = 0;
    Bytef* dest = out_size ? out : &scratch;
    uLongf dest_len = static_cast<uLongf>(out_size);
    const int rc = ::uncompress(dest, &dest_len, input.data, static_cast<uLong>(input.size));
    if (rc != Z_OK || dest_len != out_size) {
        throw vault_format_exception("compressed payload is invalid or has the wrong length");
    }
}

} // namespace pb::zlib
