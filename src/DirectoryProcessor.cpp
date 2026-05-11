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

    const std::filesystem::path canonicalRoot = std::filesystem::weakly_canonical(rootPath, errorCode);
    if (errorCode) {
        throw CryptoException("Unable to canonicalize root path: " + rootPath.string() + ": " + errorCode.message());
    }

    ProcessingResult result;
    std::set<std::filesystem::path> processedCanonicalFiles;

    const auto options = std::filesystem::directory_options::skip_permission_denied;
    std::filesystem::recursive_directory_iterator iterator(rootPath, options, errorCode);
    const std::filesystem::recursive_directory_iterator end;

    if (errorCode) {
        throw CryptoException("Unable to start recursive directory traversal: " + errorCode.message());
    }

    while (iterator != end) {
        const std::filesystem::directory_entry entry = *iterator;
        const std::filesystem::path currentPath = entry.path();

        try {
            if (shouldSkipInternalFile(currentPath)) {
                ++result.skippedFiles;
            }
            else if (entry.is_symlink(errorCode)) {
                processSymlinkToFile(
                    currentPath,
                    canonicalRoot,
                    password,
                    mode,
                    result,
                    processedCanonicalFiles);
            }
            else if (entry.is_regular_file(errorCode)) {
                processRegularFile(
                    currentPath,
                    password,
                    mode,
                    result,
                    processedCanonicalFiles);
            }
        }
        catch (const std::exception& exception) {
            ++result.failedFiles;
            m_output << "[ERROR] " << currentPath.string() << ": " << exception.what() << '\n';
        }

        iterator.increment(errorCode);
        if (errorCode) {
            ++result.failedFiles;
            m_output << "[ERROR] traversal: " << errorCode.message() << '\n';
            errorCode.clear();
        }
    }

    return result;
}

bool DirectoryProcessor::shouldSkipInternalFile(const std::filesystem::path& path) const
{
    const std::string fileName = path.filename().string();
    return fileName.rfind(".folder_protector_tmp_", 0) == 0
        || fileName.rfind(".folder_protector_backup_", 0) == 0;
}

bool DirectoryProcessor::isInsideRoot(
    const std::filesystem::path& canonicalRoot,
    const std::filesystem::path& canonicalTarget) const
{
    const auto rootString = canonicalRoot.lexically_normal().string();
    const auto targetString = canonicalTarget.lexically_normal().string();

    if (targetString == rootString) {
        return true;
    }

    std::string normalizedRoot = rootString;
    if (!normalizedRoot.empty() && normalizedRoot.back() != std::filesystem::path::preferred_separator) {
        normalizedRoot.push_back(std::filesystem::path::preferred_separator);
    }

    return targetString.rfind(normalizedRoot, 0) == 0;
}

void DirectoryProcessor::processRegularFile(
    const std::filesystem::path& filePath,
    const std::string& password,
    Mode mode,
    ProcessingResult& result,
    std::set<std::filesystem::path>& processedCanonicalFiles)
{
    std::error_code errorCode;
    const std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(filePath, errorCode);
    if (errorCode) {
        throw CryptoException("Unable to canonicalize file path: " + errorCode.message());
    }

    if (!processedCanonicalFiles.insert(canonicalPath).second) {
        ++result.skippedFiles;
        m_output << "[SKIP] already processed target: " << filePath.string() << '\n';
        return;
    }

    FileCryptor::OperationResult operationResult = FileCryptor::OperationResult::Skipped;
    if (mode == Mode::Encrypt) {
        operationResult = FileCryptor::instance().encryptFile(filePath, password);
    }
    else {
        operationResult = FileCryptor::instance().decryptFile(filePath, password);
    }

    if (operationResult == FileCryptor::OperationResult::Skipped) {
        ++result.skippedFiles;
        m_output << "[SKIP] " << filePath.string() << '\n';
        return;
    }

    if (mode == Mode::Encrypt) {
        ++result.encryptedFiles;
        m_output << "[ENCRYPTED] " << filePath.string() << '\n';
    }
    else {
        ++result.decryptedFiles;
        m_output << "[DECRYPTED] " << filePath.string() << '\n';
    }
}

void DirectoryProcessor::processSymlinkToFile(
    const std::filesystem::path& linkPath,
    const std::filesystem::path& canonicalRoot,
    const std::string& password,
    Mode mode,
    ProcessingResult& result,
    std::set<std::filesystem::path>& processedCanonicalFiles)
{
    std::error_code errorCode;
    const std::filesystem::file_status targetStatus = std::filesystem::status(linkPath, errorCode);
    if (errorCode) {
        ++result.skippedFiles;
        m_output << "[SKIP] broken symlink: " << linkPath.string() << '\n';
        return;
    }

    if (!std::filesystem::is_regular_file(targetStatus)) {
        ++result.skippedFiles;
        m_output << "[SKIP] symlink is not pointing to a regular file: " << linkPath.string() << '\n';
        return;
    }

    const std::filesystem::path canonicalTarget = std::filesystem::canonical(linkPath, errorCode);
    if (errorCode) {
        throw CryptoException("Unable to canonicalize symlink target: " + errorCode.message());
    }

    if (!isInsideRoot(canonicalRoot, canonicalTarget)) {
        ++result.skippedFiles;
        m_output << "[SKIP] symlink target is outside selected root: " << linkPath.string() << " -> "
                 << canonicalTarget.string() << '\n';
        return;
    }

    ++result.processedSymlinks;
    processRegularFile(canonicalTarget, password, mode, result, processedCanonicalFiles);
}
