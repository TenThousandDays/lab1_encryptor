#include "DirectoryProcessor.h"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

void printUsage(const char* executableName)
{
    std::cerr << "Usage:\n"
              << "  " << executableName << " encrypt <directory_path> <password>\n"
              << "  " << executableName << " decrypt <directory_path> <password>\n\n"
              << "Examples:\n"
              << "  " << executableName << " encrypt ./data \"StrongPassword123!\"\n"
              << "  " << executableName << " decrypt ./data \"StrongPassword123!\"\n";
}

bool parseMode(const std::string& value, DirectoryProcessor::Mode& mode)
{
    if (value == "encrypt") {
        mode = DirectoryProcessor::Mode::Encrypt;
        return true;
    }
    if (value == "decrypt") {
        mode = DirectoryProcessor::Mode::Decrypt;
        return true;
    }
    return false;
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        if (argc != 4) {
            printUsage(argv[0]);
            return EXIT_FAILURE;
        }

        DirectoryProcessor::Mode mode = DirectoryProcessor::Mode::Encrypt;
        if (!parseMode(argv[1], mode)) {
            printUsage(argv[0]);
            return EXIT_FAILURE;
        }

        const std::filesystem::path directoryPath = argv[2];
        const std::string password = argv[3];

        DirectoryProcessor processor(std::cout);
        const ProcessingResult result = processor.process(directoryPath, password, mode);

        std::cout << "\nSummary:\n"
                  << "  encrypted files: " << result.encryptedFiles << '\n'
                  << "  decrypted files: " << result.decryptedFiles << '\n'
                  << "  skipped files:   " << result.skippedFiles << '\n'
                  << "  failed files:    " << result.failedFiles << '\n'
                  << "  symlinks used:   " << result.processedSymlinks << '\n';

        return result.failedFiles == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    catch (const std::exception& exception) {
        std::cerr << "Fatal error: " << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    catch (...) {
        std::cerr << "Fatal error: unknown non-standard exception\n";
        return EXIT_FAILURE;
    }
}
