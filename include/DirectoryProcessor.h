#ifndef DIRECTORYPROCESSOR_H
#define DIRECTORYPROCESSOR_H

#include "ProcessingResult.h"

#include <filesystem>
#include <iosfwd>
#include <set>
#include <string>

class DirectoryProcessor final
{
public:
    enum class Mode
    {
        Encrypt,
        Decrypt
    };

    explicit DirectoryProcessor(
        std::ostream& output,
        std::filesystem::path& executablePath);

    ProcessingResult process(
        const std::filesystem::path& rootPath,
        const std::string& password,
        Mode mode);

private:
    bool shouldSkipExecutableFile(const std::filesystem::path& path) const;
    bool shouldSkipInternalFile(const std::filesystem::path& path) const;
    bool isInsideRoot(
        const std::filesystem::path& canonicalRoot,
        const std::filesystem::path& canonicalTarget) const;

    void processRegularFile(
        const std::filesystem::path& filePath,
        const std::string& password,
        Mode mode,
        ProcessingResult& result,
        std::set<std::filesystem::path>& processedCanonicalFiles);

    void processSymlinkToFile(
        const std::filesystem::path& linkPath,
        const std::filesystem::path& canonicalRoot,
        const std::string& password,
        Mode mode,
        ProcessingResult& result,
        std::set<std::filesystem::path>& processedCanonicalFiles);

    std::ostream& m_output;
    std::filesystem::path& m_executablePath;
};

#endif // DIRECTORYPROCESSOR_H
