#include <cstdlib>
#include <iostream>
#include <string>

namespace {

enum class Mode
{
    Encrypt,
    Decrypt
};

void printUsage(const char* executableName)
{
    std::cerr << "Usage:\n"
              << "  " << executableName << " encrypt <directory_path> <password>\n"
              << "  " << executableName << " decrypt <directory_path> <password>\n\n"
              << "Examples:\n"
              << "  " << executableName << " encrypt ./data \"StrongPassword123!\"\n"
              << "  " << executableName << " decrypt ./data \"StrongPassword123!\"\n";
}

bool parseMode(const std::string& value, Mode& mode)
{
    if (value == "encrypt") {
        mode = Mode::Encrypt;
        return true;
    }
    if (value == "decrypt") {
        mode = Mode::Decrypt;
        return true;
    }
    return false;
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc != 4) {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    Mode mode = Mode::Encrypt;
    if (!parseMode(argv[1], mode)) {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    std::cout << "FolderProtector args ok\n";
    return EXIT_SUCCESS;
}
