#ifndef CRYPTOEXCEPTION_H
#define CRYPTOEXCEPTION_H

#include <stdexcept>
#include <string>

class CryptoException final : public std::runtime_error
{
public:
    explicit CryptoException(const std::string& message)
        : std::runtime_error(message)
    {
    }
};

#endif // CRYPTOEXCEPTION_H
