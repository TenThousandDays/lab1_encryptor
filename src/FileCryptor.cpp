#include "FileCryptor.h"

#include "CryptoException.h"

FileCryptor& FileCryptor::instance()
{
    static FileCryptor instance;
    return instance;
}

FileCryptor::OperationResult FileCryptor::encryptFile(
    const std::filesystem::path&,
    const std::string&)
{
    throw CryptoException("Encryption is not implemented yet");
}

FileCryptor::OperationResult FileCryptor::decryptFile(
    const std::filesystem::path&,
    const std::string&)
{
    throw CryptoException("Decryption is not implemented yet");
}

bool FileCryptor::isEncryptedFile(const std::filesystem::path&) const
{
    return false;
}
