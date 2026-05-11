#include "FileCryptor.h"

#include "CryptoException.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <random>
#include <sstream>
#include <system_error>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace {

std::string opensslErrorText()
{
    const unsigned long errorCode = ERR_get_error();
    if (errorCode == 0) {
        return "OpenSSL error details are unavailable";
    }

    std::array<char, 256> buffer {};
    ERR_error_string_n(errorCode, buffer.data(), buffer.size());
    return std::string(buffer.data());
}

void writeUint32Le(std::vector<unsigned char>& data, std::uint32_t value)
{
    data.push_back(static_cast<unsigned char>(value & 0xFFU));
    data.push_back(static_cast<unsigned char>((value >> 8U) & 0xFFU));
    data.push_back(static_cast<unsigned char>((value >> 16U) & 0xFFU));
    data.push_back(static_cast<unsigned char>((value >> 24U) & 0xFFU));
}

std::uint32_t readUint32Le(const std::vector<unsigned char>& data, std::size_t offset)
{
    if (offset + 4U > data.size()) {
        throw CryptoException("Invalid encrypted file header: truncated integer field");
    }

    return static_cast<std::uint32_t>(data[offset])
        | (static_cast<std::uint32_t>(data[offset + 1U]) << 8U)
        | (static_cast<std::uint32_t>(data[offset + 2U]) << 16U)
        | (static_cast<std::uint32_t>(data[offset + 3U]) << 24U);
}

std::string randomHexSuffix()
{
    std::array<unsigned char, 8> randomBytes {};
    if (RAND_bytes(randomBytes.data(), static_cast<int>(randomBytes.size())) != 1) {
        throw CryptoException("Unable to generate random temporary file suffix: " + opensslErrorText());
    }

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const unsigned char byte : randomBytes) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

void ensureStreamIsGood(const std::ios& stream, const std::string& message)
{
    if (!stream.good()) {
        throw CryptoException(message);
    }
}

std::uintmax_t fileSizeChecked(const std::filesystem::path& filePath)
{
    std::error_code errorCode;
    const std::uintmax_t size = std::filesystem::file_size(filePath, errorCode);
    if (errorCode) {
        throw CryptoException("Unable to read file size for " + filePath.string() + ": " + errorCode.message());
    }
    return size;
}

} // namespace

FileCryptor& FileCryptor::instance()
{
    static FileCryptor instance;
    return instance;
}

void FileCryptor::EvpCipherContextDeleter::operator()(EVP_CIPHER_CTX* context) const noexcept
{
    EVP_CIPHER_CTX_free(context);
}

FileCryptor::OperationResult FileCryptor::encryptFile(
    const std::filesystem::path& filePath,
    const std::string& password)
{
    validateRegularFileForWrite(filePath);

    if (isEncryptedFile(filePath)) {
        return OperationResult::Skipped;
    }

    transformFile(filePath, password, TransformMode::Encrypt);
    return OperationResult::Processed;
}

FileCryptor::OperationResult FileCryptor::decryptFile(
    const std::filesystem::path& filePath,
    const std::string& password)
{
    validateRegularFileForWrite(filePath);

    if (!isEncryptedFile(filePath)) {
        return OperationResult::Skipped;
    }

    transformFile(filePath, password, TransformMode::Decrypt);
    return OperationResult::Processed;
}

bool FileCryptor::isEncryptedFile(const std::filesystem::path& filePath) const
{
    std::ifstream input(filePath, std::ios::binary);
    if (!input.is_open()) {
        throw CryptoException("Unable to open file for reading: " + filePath.string());
    }

    std::array<unsigned char, kMagic.size()> magic {};
    input.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
    const std::streamsize bytesRead = input.gcount();
    if (bytesRead != static_cast<std::streamsize>(magic.size())) {
        return false;
    }

    return magic == kMagic;
}

void FileCryptor::transformFile(
    const std::filesystem::path& filePath,
    const std::string& password,
    TransformMode mode)
{
    const std::filesystem::path temporaryPath = makeSiblingTemporaryPath(filePath);

    try {
        if (mode == TransformMode::Encrypt) {
            encryptToTemporaryFile(filePath, temporaryPath, password);
        }
        else {
            decryptToTemporaryFile(filePath, temporaryPath, password);
        }

        replaceOriginalWithTemporary(filePath, temporaryPath);
    }
    catch (...) {
        std::error_code removeError;
        std::filesystem::remove(temporaryPath, removeError);
        throw;
    }
}

void FileCryptor::encryptToTemporaryFile(
    const std::filesystem::path& sourcePath,
    const std::filesystem::path& temporaryPath,
    const std::string& password)
{
    std::ifstream input(sourcePath, std::ios::binary);
    if (!input.is_open()) {
        throw CryptoException("Unable to open source file for encryption: " + sourcePath.string());
    }

    std::ofstream output(temporaryPath, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw CryptoException("Unable to create temporary file: " + temporaryPath.string());
    }

    std::array<unsigned char, kSaltSize> salt {};
    std::array<unsigned char, kIvSize> iv {};
    fillRandomBytes(salt.data(), salt.size());
    fillRandomBytes(iv.data(), iv.size());

    const std::vector<unsigned char> header = buildHeader(salt, iv);
    output.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
    ensureStreamIsGood(output, "Unable to write encrypted file header: " + temporaryPath.string());

    std::array<unsigned char, kKeySize> key = deriveKey(password, salt);
    EvpCipherContextPtr context = createCipherContext();

    if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to initialize AES-256-GCM encryption: " + opensslErrorText());
    }

    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to configure AES-GCM IV length: " + opensslErrorText());
    }

    if (EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to set AES-256-GCM key and IV: " + opensslErrorText());
    }

    int processedBytes = 0;
    if (EVP_EncryptUpdate(
            context.get(),
            nullptr,
            &processedBytes,
            header.data(),
            static_cast<int>(header.size())) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to attach encrypted file header as AAD: " + opensslErrorText());
    }

    std::vector<unsigned char> inputBuffer(kBufferSize);
    std::vector<unsigned char> outputBuffer(kBufferSize + EVP_MAX_BLOCK_LENGTH);

    while (input.good()) {
        input.read(
            reinterpret_cast<char*>(inputBuffer.data()),
            static_cast<std::streamsize>(inputBuffer.size()));
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead <= 0) {
            break;
        }

        if (bytesRead > static_cast<std::streamsize>(std::numeric_limits<int>::max())) {
            OPENSSL_cleanse(key.data(), key.size());
            throw CryptoException("Input chunk is too large for OpenSSL API");
        }

        int bytesWritten = 0;
        if (EVP_EncryptUpdate(
                context.get(),
                outputBuffer.data(),
                &bytesWritten,
                inputBuffer.data(),
                static_cast<int>(bytesRead)) != 1) {
            OPENSSL_cleanse(key.data(), key.size());
            throw CryptoException("AES-256-GCM encryption failed: " + opensslErrorText());
        }

        output.write(
            reinterpret_cast<const char*>(outputBuffer.data()),
            static_cast<std::streamsize>(bytesWritten));
        ensureStreamIsGood(output, "Unable to write encrypted data: " + temporaryPath.string());
    }

    if (input.bad()) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to read source file during encryption: " + sourcePath.string());
    }

    int finalBytes = 0;
    if (EVP_EncryptFinal_ex(context.get(), outputBuffer.data(), &finalBytes) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("AES-256-GCM finalization failed: " + opensslErrorText());
    }

    if (finalBytes > 0) {
        output.write(
            reinterpret_cast<const char*>(outputBuffer.data()),
            static_cast<std::streamsize>(finalBytes));
        ensureStreamIsGood(output, "Unable to write final encrypted data: " + temporaryPath.string());
    }

    std::array<unsigned char, kTagSize> tag {};
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to get AES-GCM authentication tag: " + opensslErrorText());
    }

    output.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
    ensureStreamIsGood(output, "Unable to write AES-GCM authentication tag: " + temporaryPath.string());

    output.close();
    if (!output) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to close temporary encrypted file safely: " + temporaryPath.string());
    }

    OPENSSL_cleanse(key.data(), key.size());
}

void FileCryptor::decryptToTemporaryFile(
    const std::filesystem::path& sourcePath,
    const std::filesystem::path& temporaryPath,
    const std::string& password)
{
    const std::size_t headerSize = kMagic.size() + 1U + 1U + 1U + 1U + 4U + kSaltSize + kIvSize;
    const std::uintmax_t encryptedFileSize = fileSizeChecked(sourcePath);
    if (encryptedFileSize < headerSize + kTagSize) {
        throw CryptoException("Encrypted file is too small or corrupted: " + sourcePath.string());
    }

    std::ifstream input(sourcePath, std::ios::binary);
    if (!input.is_open()) {
        throw CryptoException("Unable to open source file for decryption: " + sourcePath.string());
    }

    std::vector<unsigned char> header(headerSize);
    input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (input.gcount() != static_cast<std::streamsize>(header.size())) {
        throw CryptoException("Unable to read encrypted file header: " + sourcePath.string());
    }

    std::array<unsigned char, kSaltSize> salt {};
    std::array<unsigned char, kIvSize> iv {};
    parseHeader(header, salt, iv);

    const std::uintmax_t cipherTextSize = encryptedFileSize - header.size() - kTagSize;
    if (cipherTextSize > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        // The streaming loop still supports large files, but a platform with a smaller streamsize is unsafe.
        throw CryptoException("Encrypted file is too large for this platform stream implementation");
    }

    std::ofstream output(temporaryPath, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw CryptoException("Unable to create temporary decrypted file: " + temporaryPath.string());
    }

    std::array<unsigned char, kKeySize> key = deriveKey(password, salt);
    EvpCipherContextPtr context = createCipherContext();

    if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to initialize AES-256-GCM decryption: " + opensslErrorText());
    }

    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to configure AES-GCM IV length: " + opensslErrorText());
    }

    if (EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to set AES-256-GCM key and IV: " + opensslErrorText());
    }

    int processedBytes = 0;
    if (EVP_DecryptUpdate(
            context.get(),
            nullptr,
            &processedBytes,
            header.data(),
            static_cast<int>(header.size())) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to attach encrypted file header as AAD: " + opensslErrorText());
    }

    std::vector<unsigned char> inputBuffer(kBufferSize);
    std::vector<unsigned char> outputBuffer(kBufferSize + EVP_MAX_BLOCK_LENGTH);

    std::uintmax_t remainingCipherTextBytes = cipherTextSize;
    while (remainingCipherTextBytes > 0U) {
        const std::size_t bytesToRead = static_cast<std::size_t>(
            std::min<std::uintmax_t>(remainingCipherTextBytes, inputBuffer.size()));
        input.read(reinterpret_cast<char*>(inputBuffer.data()), static_cast<std::streamsize>(bytesToRead));
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead != static_cast<std::streamsize>(bytesToRead)) {
            OPENSSL_cleanse(key.data(), key.size());
            throw CryptoException("Encrypted file ended unexpectedly: " + sourcePath.string());
        }

        int bytesWritten = 0;
        if (EVP_DecryptUpdate(
                context.get(),
                outputBuffer.data(),
                &bytesWritten,
                inputBuffer.data(),
                static_cast<int>(bytesRead)) != 1) {
            OPENSSL_cleanse(key.data(), key.size());
            throw CryptoException("AES-256-GCM decryption failed: " + opensslErrorText());
        }

        output.write(
            reinterpret_cast<const char*>(outputBuffer.data()),
            static_cast<std::streamsize>(bytesWritten));
        ensureStreamIsGood(output, "Unable to write decrypted data: " + temporaryPath.string());

        remainingCipherTextBytes -= static_cast<std::uintmax_t>(bytesRead);
    }

    std::array<unsigned char, kTagSize> tag {};
    input.read(reinterpret_cast<char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
    if (input.gcount() != static_cast<std::streamsize>(tag.size())) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to read AES-GCM authentication tag: " + sourcePath.string());
    }

    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to set AES-GCM authentication tag: " + opensslErrorText());
    }

    int finalBytes = 0;
    if (EVP_DecryptFinal_ex(context.get(), outputBuffer.data(), &finalBytes) != 1) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Authentication failed: wrong password or corrupted encrypted file: " + sourcePath.string());
    }

    if (finalBytes > 0) {
        output.write(
            reinterpret_cast<const char*>(outputBuffer.data()),
            static_cast<std::streamsize>(finalBytes));
        ensureStreamIsGood(output, "Unable to write final decrypted data: " + temporaryPath.string());
    }

    output.close();
    if (!output) {
        OPENSSL_cleanse(key.data(), key.size());
        throw CryptoException("Unable to close temporary decrypted file safely: " + temporaryPath.string());
    }

    OPENSSL_cleanse(key.data(), key.size());
}

std::filesystem::path FileCryptor::makeSiblingTemporaryPath(const std::filesystem::path& filePath) const
{
    const std::filesystem::path directory = filePath.parent_path();
    const std::string fileName = filePath.filename().string();

    for (int attempt = 0; attempt < 16; ++attempt) {
        const std::filesystem::path candidate = directory / (".folder_protector_tmp_" + randomHexSuffix() + "_" + fileName);
        std::error_code errorCode;
        if (!std::filesystem::exists(candidate, errorCode)) {
            return candidate;
        }
    }

    throw CryptoException("Unable to create unique temporary file path near: " + filePath.string());
}

std::filesystem::path FileCryptor::makeSiblingBackupPath(const std::filesystem::path& filePath) const
{
    const std::filesystem::path directory = filePath.parent_path();
    const std::string fileName = filePath.filename().string();

    for (int attempt = 0; attempt < 16; ++attempt) {
        const std::filesystem::path candidate = directory / (".folder_protector_backup_" + randomHexSuffix() + "_" + fileName);
        std::error_code errorCode;
        if (!std::filesystem::exists(candidate, errorCode)) {
            return candidate;
        }
    }

    throw CryptoException("Unable to create unique backup file path near: " + filePath.string());
}

void FileCryptor::replaceOriginalWithTemporary(
    const std::filesystem::path& originalPath,
    const std::filesystem::path& temporaryPath) const
{
    std::error_code metadataError;
    const auto originalPermissions = std::filesystem::status(originalPath, metadataError).permissions();
    const auto originalWriteTime = std::filesystem::last_write_time(originalPath, metadataError);

    const std::filesystem::path backupPath = makeSiblingBackupPath(originalPath);

    std::error_code renameError;
    std::filesystem::rename(originalPath, backupPath, renameError);
    if (renameError) {
        throw CryptoException("Unable to move original file to backup: " + originalPath.string() + ": " + renameError.message());
    }

    std::filesystem::rename(temporaryPath, originalPath, renameError);
    if (renameError) {
        std::error_code restoreError;
        std::filesystem::rename(backupPath, originalPath, restoreError);
        throw CryptoException("Unable to replace original file with temporary file: "
            + originalPath.string() + ": " + renameError.message());
    }

    std::error_code restoreMetadataError;
    std::filesystem::permissions(originalPath, originalPermissions, restoreMetadataError);
    std::filesystem::last_write_time(originalPath, originalWriteTime, restoreMetadataError);

    std::error_code removeError;
    std::filesystem::remove(backupPath, removeError);
    if (removeError) {
        throw CryptoException("File was processed, but backup file could not be removed: "
            + backupPath.string() + ": " + removeError.message());
    }
}

std::vector<unsigned char> FileCryptor::buildHeader(
    const std::array<unsigned char, kSaltSize>& salt,
    const std::array<unsigned char, kIvSize>& iv) const
{
    std::vector<unsigned char> header;
    header.reserve(kMagic.size() + 1U + 1U + 1U + 1U + 4U + salt.size() + iv.size());

    header.insert(header.end(), kMagic.begin(), kMagic.end());
    header.push_back(kFormatVersion);
    header.push_back(static_cast<unsigned char>(salt.size()));
    header.push_back(static_cast<unsigned char>(iv.size()));
    header.push_back(static_cast<unsigned char>(kTagSize));
    writeUint32Le(header, static_cast<std::uint32_t>(kPbkdf2Iterations));
    header.insert(header.end(), salt.begin(), salt.end());
    header.insert(header.end(), iv.begin(), iv.end());

    return header;
}

void FileCryptor::parseHeader(
    const std::vector<unsigned char>& header,
    std::array<unsigned char, kSaltSize>& salt,
    std::array<unsigned char, kIvSize>& iv) const
{
    const std::size_t expectedSize = kMagic.size() + 1U + 1U + 1U + 1U + 4U + salt.size() + iv.size();
    if (header.size() != expectedSize) {
        throw CryptoException("Invalid encrypted file header size");
    }

    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin())) {
        throw CryptoException("Invalid encrypted file magic value");
    }

    std::size_t offset = kMagic.size();
    const unsigned char version = header[offset++];
    const unsigned char saltSize = header[offset++];
    const unsigned char ivSize = header[offset++];
    const unsigned char tagSize = header[offset++];
    const std::uint32_t iterations = readUint32Le(header, offset);
    offset += 4U;

    if (version != kFormatVersion) {
        throw CryptoException("Unsupported encrypted file format version");
    }
    if (saltSize != kSaltSize || ivSize != kIvSize || tagSize != kTagSize) {
        throw CryptoException("Unsupported encrypted file cryptographic parameter size");
    }
    if (iterations != static_cast<std::uint32_t>(kPbkdf2Iterations)) {
        throw CryptoException("Unsupported PBKDF2 iteration count in encrypted file");
    }

    std::copy_n(header.begin() + static_cast<std::ptrdiff_t>(offset), salt.size(), salt.begin());
    offset += salt.size();
    std::copy_n(header.begin() + static_cast<std::ptrdiff_t>(offset), iv.size(), iv.begin());
}

std::array<unsigned char, FileCryptor::kKeySize> FileCryptor::deriveKey(
    const std::string& password,
    const std::array<unsigned char, kSaltSize>& salt) const
{
    if (password.empty()) {
        throw CryptoException("Password must not be empty");
    }

    std::array<unsigned char, kKeySize> key {};
    const int result = PKCS5_PBKDF2_HMAC(
        password.data(),
        static_cast<int>(password.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        kPbkdf2Iterations,
        EVP_sha256(),
        static_cast<int>(key.size()),
        key.data());

    if (result != 1) {
        throw CryptoException("PBKDF2-HMAC-SHA256 key derivation failed: " + opensslErrorText());
    }

    return key;
}

FileCryptor::EvpCipherContextPtr FileCryptor::createCipherContext() const
{
    EvpCipherContextPtr context(EVP_CIPHER_CTX_new());
    if (!context) {
        throw CryptoException("Unable to allocate OpenSSL EVP cipher context");
    }
    return context;
}

void FileCryptor::fillRandomBytes(unsigned char* buffer, std::size_t size) const
{
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw CryptoException("Requested random buffer is too large for OpenSSL API");
    }

    if (RAND_bytes(buffer, static_cast<int>(size)) != 1) {
        throw CryptoException("Unable to generate cryptographically secure random bytes: " + opensslErrorText());
    }
}

void FileCryptor::validateRegularFileForWrite(const std::filesystem::path& filePath) const
{
    std::error_code errorCode;
    if (!std::filesystem::exists(filePath, errorCode)) {
        throw CryptoException("File does not exist: " + filePath.string());
    }
    if (!std::filesystem::is_regular_file(filePath, errorCode)) {
        throw CryptoException("Path is not a regular file: " + filePath.string());
    }
}
