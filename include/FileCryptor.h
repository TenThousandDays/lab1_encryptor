#ifndef FILECRYPTOR_H
#define FILECRYPTOR_H

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>

class FileCryptor final
{
public:
    enum class OperationResult
    {
        Processed,
        Skipped
    };

    static FileCryptor& instance();

    FileCryptor(const FileCryptor&) = delete;
    FileCryptor& operator=(const FileCryptor&) = delete;
    FileCryptor(FileCryptor&&) = delete;
    FileCryptor& operator=(FileCryptor&&) = delete;

    OperationResult encryptFile(const std::filesystem::path& filePath, const std::string& password);
    OperationResult decryptFile(const std::filesystem::path& filePath, const std::string& password);

    bool isEncryptedFile(const std::filesystem::path& filePath) const;

private:
    struct EvpCipherContextDeleter
    {
        void operator()(EVP_CIPHER_CTX* context) const noexcept;
    };

    using EvpCipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherContextDeleter>;

    enum class TransformMode
    {
        Encrypt,
        Decrypt
    };

    static constexpr std::array<unsigned char, 8> kMagic = { 'R', 'S', 'Z', 'I', 'E', 'N', 'C', '1' };
    static constexpr unsigned char kFormatVersion = 1;
    static constexpr std::size_t kSaltSize = 16;
    static constexpr std::size_t kIvSize = 12;
    static constexpr std::size_t kTagSize = 16;
    static constexpr std::size_t kKeySize = 32;
    static constexpr int kPbkdf2Iterations = 210000;
    static constexpr std::size_t kBufferSize = 64 * 1024;

    FileCryptor() = default;

    void transformFile(
        const std::filesystem::path& filePath,
        const std::string& password,
        TransformMode mode);

    void encryptToTemporaryFile(
        const std::filesystem::path& sourcePath,
        const std::filesystem::path& temporaryPath,
        const std::string& password);

    void decryptToTemporaryFile(
        const std::filesystem::path& sourcePath,
        const std::filesystem::path& temporaryPath,
        const std::string& password);

    std::filesystem::path makeSiblingTemporaryPath(const std::filesystem::path& filePath) const;
    std::filesystem::path makeSiblingBackupPath(const std::filesystem::path& filePath) const;

    void replaceOriginalWithTemporary(
        const std::filesystem::path& originalPath,
        const std::filesystem::path& temporaryPath) const;

    std::vector<unsigned char> buildHeader(
        const std::array<unsigned char, kSaltSize>& salt,
        const std::array<unsigned char, kIvSize>& iv) const;

    void parseHeader(
        const std::vector<unsigned char>& header,
        std::array<unsigned char, kSaltSize>& salt,
        std::array<unsigned char, kIvSize>& iv) const;

    std::array<unsigned char, kKeySize> deriveKey(
        const std::string& password,
        const std::array<unsigned char, kSaltSize>& salt) const;

    EvpCipherContextPtr createCipherContext() const;
    void fillRandomBytes(unsigned char* buffer, std::size_t size) const;
    void validateRegularFileForWrite(const std::filesystem::path& filePath) const;
};

#endif // FILECRYPTOR_H
