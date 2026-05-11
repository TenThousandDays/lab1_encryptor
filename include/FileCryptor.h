#ifndef FILECRYPTOR_H
#define FILECRYPTOR_H

#include <filesystem>
#include <string>

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
    FileCryptor() = default;
};

#endif // FILECRYPTOR_H
