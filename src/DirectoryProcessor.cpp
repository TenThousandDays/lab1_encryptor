#include "DirectoryProcessor.h"

#include "CryptoException.h"
#include "FileCryptor.h"

#include <iostream>
#include <system_error>

DirectoryProcessor::DirectoryProcessor(std::ostream& output)
    : m_output(output)
{
}

ProcessingResult DirectoryProcessor::process(
    const std::filesystem::path& rootPath,
    const std::string& password,
    Mode mode)
{
    if (password.empty()) {
        throw CryptoException("Password must not be empty");
    }

    std::error_code errorCode;
    if (!std::filesystem::exists(rootPath, errorCode)) {
        throw CryptoException("Root path does not exist: " + rootPath.string());
    }
    if (!std::filesystem::is_directory(rootPath, errorCode)) {
        throw CryptoException("Root path is not a directory: " + rootPath.string());
    }

    ProcessingResult result;
    const auto options = std::filesystem::directory_options::skip_permission_denied;

    for (std::filesystem::recursive_directory_iterator iterator(rootPath, options, errorCode), end;
         iterator != end;
         iterator.increment(errorCode)) {
        if (errorCode) {
            ++result.failedFiles;
            m_output << "[ERROR] traversal: " << errorCode.message() << '\n';
            errorCode.clear();
            continue;
        }

        const std::filesystem::directory_entry entry = *iterator;
        if (!entry.is_regular_file(errorCode)) {
            continue;
        }

        try {
            FileCryptor::OperationResult operationResult = FileCryptor::OperationResult::Skipped;
            if (mode == Mode::Encrypt) {
                operationResult = FileCryptor::instance().encryptFile(entry.path(), password);
            }
            else {
                operationResult = FileCryptor::instance().decryptFile(entry.path(), password);
            }

            if (operationResult == FileCryptor::OperationResult::Skipped) {
                ++result.skippedFiles;
                m_output << "[SKIP] " << entry.path().string() << '\n';
            }
            else if (mode == Mode::Encrypt) {
                ++result.encryptedFiles;
                m_output << "[ENCRYPTED] " << entry.path().string() << '\n';
            }
            else {
                ++result.decryptedFiles;
                m_output << "[DECRYPTED] " << entry.path().string() << '\n';
            }
        }
        catch (const std::exception& exception) {
            ++result.failedFiles;
            m_output << "[ERROR] " << entry.path().string() << ": " << exception.what() << '\n';
        }
    }

    return result;
}
