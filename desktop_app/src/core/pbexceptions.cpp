#include "pbexceptions.h"

#include <cstdio>

std::string pbexception::make_message(int errorcode, const std::string& detail) {
    char code[16];
    std::snprintf(code, sizeof code, "0x%04X", static_cast<unsigned>(errorcode));
    std::string msg = std::string("PhylaxBox error ") + code;
    if (!detail.empty()) {
        msg += ": " + detail;
    }
    return msg;
}

void throwHttpException(int code, const std::string& detail) {
    switch (code) {
        case 400: throw http_exception(ErrorCodes::BAD_REQUEST, detail);
        case 401: throw authentication_exception(ErrorCodes::UNAUTHORIZED, detail);
        case 403: throw authentication_exception(ErrorCodes::FORBIDDEN, detail);
        case 404: throw notfound_exception(ErrorCodes::NOT_FOUND, detail);
        case 405: throw method_not_allowed_exception(ErrorCodes::METHOD_NOT_ALLOWED, detail);
        case 409: throw http_exception(ErrorCodes::CONFLICT, detail);
        case 429: throw unavailability_exception(ErrorCodes::TOO_MANY_REQUESTS, detail);
        case 500: throw internal_error_exception(ErrorCodes::INTERNAL_ERROR, detail);
        default: break;
    }
    if (code / 100 == 5) {
        throw unavailability_exception(ErrorCodes::OTHER_5XX_ERROR, detail);
    }
    if (code / 100 == 4) {
        throw http_exception(ErrorCodes::OTHER_4XX_ERROR, detail);
    }
    throw http_exception(code, "unexpected HTTP status " + std::to_string(code) +
                                   (detail.empty() ? "" : ": " + detail));
}
