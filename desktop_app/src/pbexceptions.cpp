#include "pbexceptions.h"

void throwHttpException(int code) {
    if (code / 100 == 4) {
        switch (code) {
            case 400:
                throw notfound_exception(ErrorCodes::BAD_REQUEST);
            case 401:
                throw authentication_exception(ErrorCodes::UNAUTHORIZED);
            case 403:
                throw authentication_exception(ErrorCodes::FORBIDDEN);
            case 404:
                throw notfound_exception(ErrorCodes::NOT_FOUND);
            case 405:
                throw method_not_allowed_exception(ErrorCodes::METHOD_NOT_ALLOWED);
            default:
                throw authentication_exception(ErrorCodes::OTHER_4XX_ERROR);
        }
    } else if (code / 100 == 5) {
        switch (code) {
            case 500:
                throw internal_error_exception(ErrorCodes::INTERNAL_ERROR);
            default:
                throw unavailability_exception(ErrorCodes::OTHER_5XX_ERROR);
        }
    }
}