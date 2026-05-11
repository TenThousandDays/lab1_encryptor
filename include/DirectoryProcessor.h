#ifndef DIRECTORYPROCESSOR_H
#define DIRECTORYPROCESSOR_H

#include "ProcessingResult.h"

#include <filesystem>
#include <iosfwd>
#include <string>

class DirectoryProcessor final
{
public:
    enum class Mode
    {
        Encrypt,
        Decrypt
    };

    explicit DirectoryProcessor(std::ostream& output);

    ProcessingResult process(
        const std::filesystem::path& rootPath,
        const std::string& password,
        Mode mode);

private:
    std::ostream& m_output;
};

#endif // DIRECTORYPROCESSOR_H
