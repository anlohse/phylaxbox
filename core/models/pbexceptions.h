#ifndef _PB_EXCEPTIONS_H_
#define _PB_EXCEPTIONS_H_

#include <stdexcept>
#include <string>

struct ErrorCodes {

    static constexpr int BAD_REQUEST        = 0x0400;
    static constexpr int UNAUTHORIZED       = 0x0401;
    static constexpr int FORBIDDEN          = 0x0403;
    static constexpr int NOT_FOUND          = 0x0404;
    static constexpr int METHOD_NOT_ALLOWED = 0x0405;
    static constexpr int CONFLICT           = 0x0409;
    static constexpr int TOO_MANY_REQUESTS  = 0x0429;
    static constexpr int OTHER_4XX_ERROR    = 0x0499;

    static constexpr int INTERNAL_ERROR     = 0x0500;
    static constexpr int OTHER_5XX_ERROR    = 0x0599;

    static constexpr int FILE_NOT_FOUND     = 0x1001;
    static constexpr int CANT_CREATE_FILE   = 0x1002;
    static constexpr int ERROR_WRITING      = 0x1003;
    static constexpr int ERROR_READING      = 0x1004;

    static constexpr int INVALID_FORMAT      = 0x2001;
    static constexpr int UNSUPPORTED_VERSION = 0x2002;
    static constexpr int WRONG_CONTENT_TYPE  = 0x2003;
    static constexpr int WRONG_PASSWORD      = 0x2004;
    static constexpr int INTEGRITY_FAILURE   = 0x2005;
    static constexpr int CRYPTO_FAILURE      = 0x2006;
    static constexpr int VAULT_LOCKED        = 0x2007;
    static constexpr int NO_RECOVERY_SLOT    = 0x2008;
    static constexpr int INVALID_RECOVERY_KEY = 0x2009;

    static constexpr int NETWORK_ERROR       = 0x3001;
    static constexpr int SYNC_CONFLICT       = 0x3002;
    static constexpr int NOT_LINKED          = 0x3003;
    static constexpr int OAUTH_TIMEOUT       = 0x3004;
    static constexpr int NOT_IMPLEMENTED     = 0x3005;
};

// Maps an HTTP error status to the matching exception. Always throws.
[[noreturn]] void throwHttpException(int code, const std::string& detail = std::string());

class pbexception : public std::runtime_error {
protected:
    const int m_errorcode;
public:
    explicit pbexception(const int errorcode, const std::string& detail = std::string())
            : std::runtime_error(make_message(errorcode, detail)), m_errorcode(errorcode) {}

    int errorcode() const {
        return m_errorcode;
    }

private:
    static std::string make_message(int errorcode, const std::string& detail);
};

class http_exception : public pbexception {
public:
    explicit http_exception(const int errorcode, const std::string& detail = std::string())
            : pbexception(errorcode, detail) {}

};


class authentication_exception : public http_exception {
public:
    explicit authentication_exception(const int errorcode, const std::string& detail = std::string())
            : http_exception(errorcode, detail) {}

};

class notfound_exception : public http_exception {
public:
    explicit notfound_exception(const int errorcode, const std::string& detail = std::string())
            : http_exception(errorcode, detail) {}

};

class method_not_allowed_exception : public http_exception {
public:
    explicit method_not_allowed_exception(const int errorcode, const std::string& detail = std::string())
            : http_exception(errorcode, detail) {}

};

class internal_error_exception : public http_exception {
public:
    explicit internal_error_exception(const int errorcode, const std::string& detail = std::string())
            : http_exception(errorcode, detail) {}

};

// Server overloaded, rate limited (429) or 5xx: retrying later may succeed.
class unavailability_exception : public http_exception {
public:
    explicit unavailability_exception(const int errorcode, const std::string& detail = std::string())
            : http_exception(errorcode, detail) {}

};

// The request never got an HTTP response (DNS, TLS, connection, timeout).
class network_exception : public pbexception {
public:
    explicit network_exception(const std::string& detail)
            : pbexception(ErrorCodes::NETWORK_ERROR, detail) {}
};

// The remote file changed since it was downloaded (another device saved it).
// Download again, merge, and retry the upload.
class sync_conflict_exception : public pbexception {
public:
    explicit sync_conflict_exception(const std::string& detail)
            : pbexception(ErrorCodes::SYNC_CONFLICT, detail) {}
};

class ioexception : public pbexception {
protected:
    const std::string m_filename;
public:
    explicit ioexception(const int errorcode, const std::string& filename)
            : pbexception(errorcode, filename), m_filename(filename) {}

    const std::string& filename() const {
        return m_filename;
    }
};

// The file is not a valid PhylaxBox container (bad magic, truncated, reserved
// fields set, unexpected content type, unsupported version...).
class vault_format_exception : public pbexception {
public:
    explicit vault_format_exception(const std::string& detail,
                                    const int errorcode = ErrorCodes::INVALID_FORMAT)
            : pbexception(errorcode, detail) {}
};

// The vault key could not be unwrapped: wrong password or recovery key (or a
// damaged key slot).
class wrong_password_exception : public pbexception {
public:
    explicit wrong_password_exception(const std::string& detail = "wrong password")
            : pbexception(ErrorCodes::WRONG_PASSWORD, detail) {}
};

// The password was right but the payload failed authentication: the file was
// corrupted or tampered with.
class integrity_exception : public pbexception {
public:
    explicit integrity_exception(const std::string& detail)
            : pbexception(ErrorCodes::INTEGRITY_FAILURE, detail) {}
};

class crypto_exception : public pbexception {
public:
    explicit crypto_exception(const std::string& detail)
            : pbexception(ErrorCodes::CRYPTO_FAILURE, detail) {}
};

#endif // _PB_EXCEPTIONS_H_
