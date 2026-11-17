#ifndef _PB_EXCEPTIONS_H_
#define _PB_EXCEPTIONS_H_

#include <stdexcept>

struct ErrorCodes {
    
    static constexpr int BAD_REQUEST        = 0x0400;
    static constexpr int UNAUTHORIZED       = 0x0401;
    static constexpr int FORBIDDEN          = 0x0403;
    static constexpr int NOT_FOUND          = 0x0404;
    static constexpr int METHOD_NOT_ALLOWED = 0x0405;
    static constexpr int OTHER_4XX_ERROR    = 0x0499;
    
    static constexpr int INTERNAL_ERROR     = 0x0500;
    static constexpr int OTHER_5XX_ERROR    = 0x0599;

    static constexpr int FILE_NOT_FOUND     = 0x1001;
    static constexpr int CANT_CREATE_FILE   = 0x1002;
    static constexpr int ERROR_WRITING      = 0x1003;
    static constexpr int ERROR_READING      = 0x1004;
};

void throwHttpException(int code);

class pbexception : public std::runtime_error {
protected:
    const int m_errorcode;
public:
    explicit pbexception(const int errorcode)
            : std::runtime_error("PhylaxBox error: " + errorcode), m_errorcode(errorcode) {}

    int errorcode() const {
        return m_errorcode;
    }
};

class http_exception : public pbexception {
public:
    explicit http_exception(const int errorcode)
            : pbexception(errorcode) {}

};
    
    
class authentication_exception : public http_exception {
public:
    explicit authentication_exception(const int errorcode)
            : http_exception(errorcode) {}

};

class notfound_exception : public http_exception {
public:
    explicit notfound_exception(const int errorcode)
            : http_exception(errorcode) {}

};

class method_not_allowed_exception : public http_exception {
public:
    explicit method_not_allowed_exception(const int errorcode)
            : http_exception(errorcode) {}

};
    
class internal_error_exception : public http_exception {
public:
    explicit internal_error_exception(const int errorcode)
            : http_exception(errorcode) {}

};
        
class unavailability_exception : public http_exception {
public:
    explicit unavailability_exception(const int errorcode)
            : http_exception(errorcode) {}

};

class ioexception : public pbexception {
protected:
    const std::string m_filename;
public:
    explicit ioexception(const int errorcode, const std::string& filename)
            : pbexception(errorcode), m_filename(filename) {}

    const std::string& filename() const {
        return m_filename;
    }
};
             
#endif // _PB_EXCEPTIONS_H_
